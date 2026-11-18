import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import type { LedgerEntry } from "../ledger/types.js";

/** ssh-keygen -Y의 namespace. 서명 안에 이 값이 들어가므로, 같은 키로 만든
 * git 커밋 서명("git")이나 다른 용도의 서명을 승인 서명으로 재사용할 수 없다
 * (PROTOCOL.sshsig 참고). */
export const APPROVAL_NAMESPACE = "vibe-supervisor-approval";

/** 원장 approved payload에 들어가는 서명. payload 전체가 해시 체인에 들어가므로
 * 서명을 떼어내거나 바꿔도 체인에서 걸린다. */
export interface ApprovalSignature {
  format: "ssh";
  namespace: string;
  /** 서명한 공개키의 SHA256 지문 — 리포트·verify 출력에 표시용. */
  fingerprint: string;
  /** ssh-keygen -Y sign 출력 (-----BEGIN SSH SIGNATURE----- …) */
  signature: string;
}

/** 서명 대상. 승인 행위를 특정하는 값만 넣는다 — 원장 레코드의 timestamp는
 * append 시점에 정해지므로 넣지 않고, 대신 commitHash로 "어느 시점 코드에 대한
 * 승인인가"를 묶는다. */
export interface ApprovalClaim {
  findingId: number;
  decision: string;
  note: string | null;
  ruleId: string;
  file: string;
  line: number;
  actor: string;
  commitHash: string;
}

/** 서명하는 바이트와 검증하는 바이트가 1바이트라도 다르면 검증이 실패하므로,
 * 키 순서를 고정한 JSON으로 만든다. v는 형식이 바뀔 때를 대비한 버전. */
export function approvalMessage(c: ApprovalClaim): string {
  return JSON.stringify({
    v: 1,
    findingId: c.findingId,
    decision: c.decision,
    note: c.note,
    ruleId: c.ruleId,
    file: c.file,
    line: c.line,
    actor: c.actor,
    commitHash: c.commitHash,
  });
}

function gitConfig(repoRoot: string, key: string): string | null {
  try {
    return execFileSync("git", ["config", "--get", key], {
      cwd: repoRoot,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim() || null;
  } catch {
    return null;
  }
}

function expandHome(p: string): string {
  return p.startsWith("~/") ? join(homedir(), p.slice(2)) : p;
}

/** 어떤 키로 서명할지. 명시적으로 준 경로가 우선이고, 없으면 git이 커밋 서명에
 * 쓰는 설정(gpg.format=ssh + user.signingkey)을 그대로 따른다 — 사용자가 키를
 * 두 군데 설정하지 않아도 되게. GPG 키는 지원하지 않는다(null). */
export function resolveSigningKey(repoRoot: string, explicit?: string): string | null {
  if (explicit) return expandHome(explicit);
  if (gitConfig(repoRoot, "gpg.format") !== "ssh") return null;
  const key = gitConfig(repoRoot, "user.signingkey");
  return key ? expandHome(key) : null;
}

/** git과 같은 규칙: user.signingkey에 경로 대신 공개키 문자열("key::ssh-…" 또는
 * "ssh-…")을 직접 넣을 수 있다. 그 경우 임시 파일로 써서 넘긴다(개인키는
 * ssh-agent에 있어야 함). */
function withKeyFile<T>(key: string, fn: (path: string) => T): T {
  const literal = key.startsWith("key::") ? key.slice(5) : /^(ssh-|ecdsa-|sk-)/.test(key) ? key : null;
  if (!literal) return fn(key);
  const dir = mkdtempSync(join(tmpdir(), "vs-sigkey-"));
  try {
    const p = join(dir, "key.pub");
    writeFileSync(p, literal + "\n");
    return fn(p);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function fingerprintOf(keyPath: string): string {
  // 개인키 경로를 줘도 ssh-keygen -l은 짝이 되는 공개키 지문을 낸다.
  const out = execFileSync("ssh-keygen", ["-l", "-f", keyPath], { encoding: "utf-8" });
  return out.split(/\s+/)[1] ?? "unknown";
}

/** 서명에 실패하면 던진다 — 서명하겠다고 해놓고 조용히 미서명으로 기록하면
 * "서명된 줄 알았다"는 오해가 생긴다. */
export function signApproval(keyPath: string, claim: ApprovalClaim): ApprovalSignature {
  return withKeyFile(keyPath, (path) => {
    // 메시지는 stdin으로 넘긴다 — 파일 인자로 주면 ssh-keygen이 옆에 .sig 파일을
    // 만들고, 이미 있으면 덮어쓸지 대화형으로 물어 멈춘다.
    const signature = execFileSync("ssh-keygen", ["-Y", "sign", "-f", path, "-n", APPROVAL_NAMESPACE], {
      input: approvalMessage(claim),
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { format: "ssh", namespace: APPROVAL_NAMESPACE, fingerprint: fingerprintOf(path), signature };
  });
}

/**
 * - valid: 서명 자체는 맞음(서명 안에 든 공개키로 검증). 그 키가 actor 본인 것인지는 모름.
 * - trusted: allowed_signers 파일에서 actor(이메일) 이름으로 등록된 키로 검증됨.
 * - untrusted: 서명은 맞지만 allowed_signers에 actor의 키로 등록돼 있지 않음.
 * - invalid: 서명이 승인 내용과 안 맞음(내용 변조) 또는 서명 형식 오류.
 */
export type ApprovalSignatureStatus = "valid" | "trusted" | "untrusted" | "invalid";

export interface ApprovalSignatureCheck {
  status: ApprovalSignatureStatus;
  fingerprint: string;
  message: string;
}

function runCheck(args: string[], sig: string, msg: string): { ok: boolean; out: string } {
  const dir = mkdtempSync(join(tmpdir(), "vs-sigchk-"));
  try {
    const sigPath = join(dir, "approval.sig");
    writeFileSync(sigPath, sig);
    const out = execFileSync("ssh-keygen", [...args, "-s", sigPath], {
      input: msg,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { ok: true, out: out.trim() };
  } catch (e) {
    const err = e as { stderr?: string; stdout?: string };
    return { ok: false, out: `${err.stdout ?? ""}${err.stderr ?? ""}`.trim() };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export function checkApprovalSignature(
  sig: ApprovalSignature,
  claim: ApprovalClaim,
  allowedSignersFile?: string
): ApprovalSignatureCheck {
  const msg = approvalMessage(claim);
  // namespace는 저장된 값이 아니라 상수로 검증한다 — 저장된 값을 믿으면 다른
  // 용도로 만든 서명을 namespace 필드만 바꿔 끼워 넣을 수 있다.
  const base = runCheck(["-Y", "check-novalidate", "-n", APPROVAL_NAMESPACE], sig.signature, msg);
  if (!base.ok) {
    return {
      status: "invalid",
      fingerprint: sig.fingerprint,
      message: `서명이 승인 내용과 일치하지 않습니다 (${base.out.split("\n")[0] || "검증 실패"}).`,
    };
  }
  const fp = base.out.match(/SHA256:\S+/)?.[0] ?? sig.fingerprint;
  if (!allowedSignersFile) {
    return { status: "valid", fingerprint: fp, message: `서명 유효 (키 ${fp}) — 키 소유자 확인은 하지 않음.` };
  }
  const trusted = runCheck(
    ["-Y", "verify", "-f", expandHome(allowedSignersFile), "-I", claim.actor, "-n", APPROVAL_NAMESPACE],
    sig.signature,
    msg
  );
  return trusted.ok
    ? { status: "trusted", fingerprint: fp, message: `서명 유효, 키 ${fp}가 ${claim.actor}의 등록 키와 일치.` }
    : {
        status: "untrusted",
        fingerprint: fp,
        message: `서명은 유효하지만 키 ${fp}가 허용 서명자 목록에 ${claim.actor}의 키로 등록돼 있지 않습니다.`,
      };
}

export function resolveAllowedSigners(repoRoot: string, explicit?: string): string | undefined {
  return explicit ?? gitConfig(repoRoot, "gpg.ssh.allowedSignersFile") ?? undefined;
}

export interface LedgerApprovalCheck {
  entryId: number;
  findingId: number;
  actor: string;
  /** null = 서명 없이 기록된 승인 */
  check: ApprovalSignatureCheck | null;
}

export interface ApprovalSignatureSummary {
  checks: LedgerApprovalCheck[];
  total: number;
  unsigned: number;
  /** valid + trusted */
  good: number;
  trusted: number;
  /** invalid + untrusted — verify를 실패시키는 것들 */
  failed: LedgerApprovalCheck[];
  allowedSignersUsed: boolean;
}

/** 원장의 승인 레코드마다 서명을 다시 검증한다. 원장 체인이 이미 "레코드가
 * 바뀌지 않았다"를 보장하므로, 여기서는 "그 레코드를 만든 사람이 그 키의
 * 소유자인가"를 따진다. 서명 없는 승인은 실패가 아니라 따로 센다 — 서명은
 * 선택 기능이고, 리포트에 비율로 드러난다. */
export function checkLedgerApprovals(
  entries: LedgerEntry[],
  allowedSignersFile?: string
): ApprovalSignatureSummary {
  const checks: LedgerApprovalCheck[] = [];
  for (const e of entries) {
    const p = e.payload;
    if (p?.kind !== "approved") continue;
    const claim: ApprovalClaim = {
      findingId: p.findingId,
      decision: p.decision,
      note: p.note,
      ruleId: p.ruleId,
      file: p.file,
      line: p.line,
      actor: e.actor,
      commitHash: e.commitHash,
    };
    checks.push({
      entryId: e.id,
      findingId: p.findingId,
      actor: e.actor,
      check: p.signature ? checkApprovalSignature(p.signature, claim, allowedSignersFile) : null,
    });
  }
  const signed = checks.filter((c) => c.check);
  return {
    checks,
    total: checks.length,
    unsigned: checks.length - signed.length,
    good: signed.filter((c) => c.check!.status === "valid" || c.check!.status === "trusted").length,
    trusted: signed.filter((c) => c.check!.status === "trusted").length,
    failed: signed.filter((c) => c.check!.status === "invalid" || c.check!.status === "untrusted"),
    allowedSignersUsed: Boolean(allowedSignersFile),
  };
}
