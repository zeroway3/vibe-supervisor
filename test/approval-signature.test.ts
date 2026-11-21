import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  approvalMessage,
  checkApprovalSignature,
  checkLedgerApprovals,
  signApproval,
  type ApprovalClaim,
} from "../src/signing/approval.js";
import type { LedgerEntry } from "../src/ledger/types.js";

function newKey(dir: string, name = "id"): string {
  const p = join(dir, name);
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", name, "-f", p]);
  return p;
}

const claim: ApprovalClaim = {
  findingId: 3,
  decision: "exception",
  note: "내부 배치 전용 — 다음 분기 재검토",
  ruleId: "ko-baseline.sql-string-concat",
  file: "src/main/java/com/example/user/UserRepository.java",
  line: 14,
  actor: "dev@example.com",
  commitHash: "a".repeat(40),
};

test("서명한 승인은 같은 내용으로 검증하면 유효하다", () => {
  const dir = mkdtempSync(join(tmpdir(), "vs-apsig-"));
  const sig = signApproval(newKey(dir), claim);
  assert.match(sig.signature, /BEGIN SSH SIGNATURE/);
  assert.match(sig.fingerprint, /^SHA256:/);
  const r = checkApprovalSignature(sig, claim);
  assert.equal(r.status, "valid");
  assert.equal(r.fingerprint, sig.fingerprint);
});

test("공개키 경로를 줘도(개인키가 옆에 있으면) 서명된다 — git user.signingkey가 보통 .pub이라서", () => {
  const dir = mkdtempSync(join(tmpdir(), "vs-apsig-"));
  const key = newKey(dir);
  const sig = signApproval(key + ".pub", claim);
  assert.equal(checkApprovalSignature(sig, claim).status, "valid");
});

test("사유·결정·대상·처리자·커밋 중 하나라도 바뀌면 invalid", () => {
  const dir = mkdtempSync(join(tmpdir(), "vs-apsig-"));
  const sig = signApproval(newKey(dir), claim);
  const variants: Partial<ApprovalClaim>[] = [
    { note: "사유 몰래 수정" },
    { decision: "approved" },
    { line: 15 },
    { file: "src/Other.java" },
    { actor: "boss@example.com" },
    { commitHash: "b".repeat(40) },
    { findingId: 4 },
  ];
  for (const v of variants) {
    assert.equal(checkApprovalSignature(sig, { ...claim, ...v }).status, "invalid", JSON.stringify(v));
  }
});

test("다른 용도(namespace)로 만든 서명은 승인 서명으로 인정하지 않는다", () => {
  const dir = mkdtempSync(join(tmpdir(), "vs-apsig-"));
  const key = newKey(dir);
  const sig = signApproval(key, claim);
  // 같은 키·같은 내용이지만 git 커밋 서명용 namespace로 서명한 것을 끼워 넣는 공격
  const gitNsSig = execFileSync("ssh-keygen", ["-Y", "sign", "-f", key, "-n", "git"], {
    input: approvalMessage(claim),
    encoding: "utf-8",
    stdio: ["pipe", "pipe", "pipe"],
  });
  const forged = { ...sig, namespace: "vibe-supervisor-approval", signature: gitNsSig };
  assert.equal(checkApprovalSignature(forged, claim).status, "invalid");
});

test("허용 서명자 목록: 본인 키면 trusted, 남의 키로 본인 이메일을 주장하면 untrusted", () => {
  const dir = mkdtempSync(join(tmpdir(), "vs-apsig-"));
  const devKey = newKey(dir, "dev");
  const otherKey = newKey(dir, "other");
  const allowed = join(dir, "allowed_signers");
  writeFileSync(allowed, `dev@example.com ${readFileSync(devKey + ".pub", "utf-8")}`);

  assert.equal(checkApprovalSignature(signApproval(devKey, claim), claim, allowed).status, "trusted");
  assert.equal(checkApprovalSignature(signApproval(otherKey, claim), claim, allowed).status, "untrusted");
});

function approvalEntry(id: number, c: ApprovalClaim, signature?: ReturnType<typeof signApproval>): LedgerEntry {
  return {
    id,
    timestamp: "2026-11-07T00:00:00.000Z",
    prevHash: null,
    hash: "x",
    eventType: "approved",
    commitHash: c.commitHash,
    actor: c.actor,
    aiTool: null,
    originConfidence: "confirmed",
    fileHashes: [],
    payload: {
      kind: "approved",
      findingId: c.findingId,
      decision: c.decision as "exception",
      note: c.note,
      ruleId: c.ruleId,
      file: c.file,
      line: c.line,
      ...(signature ? { signature } : {}),
    },
  };
}

test("원장 재계산 공격: 체인을 새로 맞춰도 서명된 승인의 사유를 바꾸면 서명 검증에서 걸린다", () => {
  const dir = mkdtempSync(join(tmpdir(), "vs-apsig-"));
  const sig = signApproval(newKey(dir), claim);
  // 공격자가 원장 payload의 사유를 바꾸고 체인 해시를 전부 다시 계산했다고 가정 —
  // 체인 검사는 통과하지만 서명은 원래 사유에 대한 것이다.
  const tampered = approvalEntry(7, { ...claim, note: "문제없음 확인" }, sig);
  const summary = checkLedgerApprovals([tampered]);
  assert.equal(summary.failed.length, 1);
  assert.equal(summary.failed[0].check?.status, "invalid");
});

test("서명 없는 승인은 실패가 아니라 unsigned로 따로 센다 (구버전 원장 호환)", () => {
  const dir = mkdtempSync(join(tmpdir(), "vs-apsig-"));
  const sig = signApproval(newKey(dir), claim);
  const summary = checkLedgerApprovals([
    approvalEntry(1, { ...claim, findingId: 1 }),
    approvalEntry(2, claim, sig),
  ]);
  assert.equal(summary.total, 2);
  assert.equal(summary.unsigned, 1);
  assert.equal(summary.good, 1);
  assert.equal(summary.failed.length, 0);
});
