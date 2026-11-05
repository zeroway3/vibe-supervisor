#!/usr/bin/env node
import { Command } from "commander";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Ledger } from "../ledger/db.js";
import { FindingsStore } from "../findings/store.js";
import { isSemgrepAvailable, scanAndRecord } from "../scan/run.js";
import { generateReport } from "../report/generate.js";
import { renderReportHtml } from "../report/html.js";
import { AnchorStore } from "../timestamp/store.js";
import { requestTimestamp, KNOWN_TSA_URLS } from "../timestamp/rfc3161.js";
import { runAudit } from "../audit.js";
import { DECISION_LABEL, type FindingDecision } from "../report/types.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const HOOK_SCRIPT = join(__dirname, "..", "hooks", "post-commit.js");
// 패키지 루트 기준 고정 룰셋 — repo 어디서 vibe-supervisor를 실행해도 항상
// 같은 룰 파일을 쓴다(재현성의 전제조건).
const RULESET_PATH = join(__dirname, "..", "..", "rulesets", "ko-baseline-v1.yaml");

function vsDir(repoRoot: string) {
  return join(repoRoot, ".vibe-supervisor");
}

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf-8" }).trim();
}

function requireLedger(repoRoot: string): string {
  const ledgerPath = join(vsDir(repoRoot), "ledger.db");
  if (!existsSync(ledgerPath)) {
    console.error("원장이 아직 없습니다 — 커밋을 먼저 해보세요.");
    process.exit(1);
  }
  return ledgerPath;
}

function readTrustedPem(path: string | undefined): string | undefined {
  if (!path) return undefined;
  if (!existsSync(path)) {
    console.error(`신뢰 루트 인증서 파일이 없습니다: ${path}`);
    process.exit(1);
  }
  return readFileSync(path, "utf-8");
}

const program = new Command();
program.name("vibe-supervisor").description(
  "AI 생성 코드에 대한 감독 계층 — git 훅으로 변조 불가능한 감독 원장을 남긴다"
);

program
  .command("install")
  .description("현재 저장소의 .git/hooks/post-commit에 연결한다")
  .action(() => {
    const repoRoot = git(["rev-parse", "--show-toplevel"], process.cwd());
    const hookPath = join(repoRoot, ".git", "hooks", "post-commit");

    if (existsSync(hookPath)) {
      console.error(
        `이미 post-commit 훅이 있습니다 (${hookPath}). 기존 훅을 덮어쓰지 않습니다 — ` +
          `수동으로 'node ${HOOK_SCRIPT}' 호출을 추가해주세요.`
      );
      process.exit(1);
    }

    // Windows 경로의 역슬래시는 sh에서 이스케이프로 읽히므로 슬래시로 바꾼다.
    writeFileSync(hookPath, `#!/bin/sh\nnode "${HOOK_SCRIPT.replace(/\\/g, "/")}"\n`);
    chmodSync(hookPath, 0o755);
    console.log(`post-commit 훅을 설치했습니다: ${hookPath}`);
    if (!isSemgrepAvailable()) {
      console.log("(참고) semgrep이 없어 커밋 시점 검사는 건너뜁니다. 'pip install semgrep' 또는 'docker pull semgrep/semgrep:1.95.0' 후 자동으로 동작합니다.");
    }
  });

program
  .command("verify")
  .description("원장 해시 체인 + 발견사항·승인 대조 + 외부 타임스탬프 서명까지 검증한다")
  .option("--tsa-ca <pem>", "TSA 신뢰 루트 인증서(PEM). 주면 서명자 인증서 체인까지 확인한다")
  .action(async (opts) => {
    const repoRoot = git(["rev-parse", "--show-toplevel"], process.cwd());
    requireLedger(repoRoot);
    const audit = await runAudit(repoRoot, readTrustedPem(opts.tsaCa));

    // 1) 해시 체인
    if (audit.integrity.ok) {
      console.log(`[1/3] 체인 무결성 OK — 원장 ${audit.entries.length}건, 변조 흔적 없음.`);
    } else {
      console.error(`[1/3] 체인 깨짐 — id=${audit.integrity.brokenAtId} 이후 기록이 원래 해시와 안 맞습니다.`);
    }

    // 2) findings.db는 체인 밖이라, 체인에 고정된 탐지·승인 기록과 대조한다.
    const cc = audit.crossCheck;
    if (cc.issues.length === 0) {
      console.log(
        `[2/3] 발견사항·승인 대조 OK — ${cc.verified}건 원장과 일치` +
          `${cc.unverifiable > 0 ? ` (구버전 기록 ${cc.unverifiable}건은 대조 근거 없음)` : ""}.`
      );
    } else {
      console.error(`[2/3] 발견사항·승인 기록 불일치 ${cc.issues.length}건:`);
      for (const i of cc.issues) console.error(`  - 발견사항 #${i.findingId}: ${i.message}`);
    }

    // 3) 앵커: 저장된 TSA 토큰의 서명을 검증하고, 서명된 해시가 "지금 원장"의
    // 해당 레코드 해시와 같은지 본다. 원장을 통째로 다시 만들면(Q4-2에서 스스로
    // 짚은 구멍) 체인은 내부적으로 일관돼도 여기서 걸린다. anchors.db까지
    // 같이 고쳐도 TSA 서명은 다시 만들 수 없어서 걸린다.
    if (audit.anchorChecks.length === 0) {
      console.log("[3/3] (참고) 외부 타임스탬프 앵커가 아직 없습니다 — 'vibe-supervisor anchor'로 추가할 수 있습니다.");
    } else {
      for (const a of audit.anchorChecks) {
        if (a.token.ok) continue;
        console.error(
          `[3/3] 앵커 #${a.anchor.id} 실패 — 원장 #${a.anchor.ledgerEntryId}: ${a.token.message} ` +
            `이 시점 이전 기록이 나중에 다시 생성됐거나 앵커가 조작됐을 가능성이 있습니다.`
        );
      }
      const passed = audit.anchorChecks.filter((a) => a.token.ok);
      if (passed.length === audit.anchorChecks.length) {
        const latest = passed[passed.length - 1].token;
        console.log(
          `[3/3] 외부 타임스탬프 앵커 ${passed.length}건 서명·해시 모두 일치 — ` +
            `가장 최근 앵커(${latest.genTime}, 서명자 ${latest.signer}) 시점까지는 소급 재생성되지 않았음을 확인.`
        );
        if (!latest.chainChecked) {
          console.log("      (참고) TSA 인증서 체인은 확인하지 않았습니다 — '--tsa-ca <루트인증서.pem>'으로 확인할 수 있습니다.");
        }
      }
    }

    if (!audit.ok) process.exit(1);
  });

program
  .command("anchor")
  .description("원장 체인의 현재 끝 해시를 외부 RFC3161 타임스탬프 기관(TSA)에 등록한다 — 소급 재생성 방지용")
  .option("--tsa <url>", "TSA 엔드포인트 URL", KNOWN_TSA_URLS.freetsa)
  .action(async (opts) => {
    const repoRoot = git(["rev-parse", "--show-toplevel"], process.cwd());
    const ledgerPath = requireLedger(repoRoot);

    const ledger = new Ledger(ledgerPath);
    const entries = ledger.all();
    const integrity = ledger.verify();
    ledger.close();

    if (entries.length === 0) {
      console.error("원장에 기록이 없습니다.");
      process.exit(1);
    }
    // 이미 깨진 체인에 도장을 찍으면 "깨진 상태"를 외부 기관이 보증해주는 꼴이 된다.
    if (!integrity.ok) {
      console.error(`체인이 깨져 있어 앵커를 등록하지 않습니다 (id=${integrity.brokenAtId}). 'verify'로 먼저 확인하세요.`);
      process.exit(1);
    }
    const tip = entries[entries.length - 1];

    console.log(`[vibe-supervisor] ${opts.tsa}에 원장 #${tip.id}(hash=${tip.hash.slice(0, 16)}…) 타임스탬프 요청 중...`);
    try {
      // requestTimestamp 안에서 nonce·imprint·서명을 확인한 토큰만 돌려준다.
      const result = await requestTimestamp(Buffer.from(tip.hash, "utf-8"), opts.tsa);

      const anchorStore = new AnchorStore(join(vsDir(repoRoot), "anchors.db"));
      const anchor = anchorStore.save({
        ledgerEntryId: tip.id,
        anchoredHash: tip.hash,
        tsaUrl: opts.tsa,
        genTime: result.genTime,
        serialNumber: result.serialNumberHex,
        tokenDer: result.tokenDer,
      });
      anchorStore.close();

      console.log(
        `[vibe-supervisor] 앵커 #${anchor.id} 저장 완료 — TSA가 ${result.genTime}에 서명 ` +
          `(serial=${result.serialNumberHex}, 서명·nonce 검증 통과). 'verify'로 언제든 재확인 가능.`
      );
    } catch (err: any) {
      console.error(`타임스탬프 요청 실패: ${err.message}`);
      process.exit(1);
    }
  });

program
  .command("log")
  .description("원장에 쌓인 기록을 최근순으로 보여준다")
  .action(() => {
    const repoRoot = git(["rev-parse", "--show-toplevel"], process.cwd());
    const ledger = new Ledger(requireLedger(repoRoot));
    const entries = ledger.all();
    ledger.close();

    for (const e of entries.slice().reverse()) {
      const p = e.payload;
      const detail =
        p?.kind === "detected"
          ? `탐지 ${p.findings.length}건`
          : p?.kind === "approved"
            ? `발견사항 #${p.findingId} ${DECISION_LABEL[p.decision]}`
            : `${e.originConfidence}${e.aiTool ? `(${e.aiTool}${p?.kind === "generated" && p.aiRatio !== null ? `, ratio=${p.aiRatio}` : ""})` : ""}  파일 ${e.fileHashes.length}개`;
      console.log(
        `#${e.id}  ${e.timestamp}  ${e.eventType.padEnd(9)} ${e.commitHash.slice(0, 8)}  ${e.actor}  ${detail}  hash=${e.hash.slice(0, 12)}…`
      );
    }
  });

program
  .command("scan")
  .description("고정 룰셋(rulesets/ko-baseline-v1.yaml)으로 저장소를 검사하고 발견사항을 원장에 남긴다")
  .option("--all", "변경 파일이 아니라 저장소 전체를 검사한다 (기본: HEAD 커밋에서 바뀐 파일만 증분 검사)")
  .action((opts) => {
    const repoRoot = git(["rev-parse", "--show-toplevel"], process.cwd());
    const commitHash = git(["rev-parse", "HEAD"], repoRoot);

    if (!isSemgrepAvailable()) {
      console.error("semgrep을 찾을 수 없습니다 — 'pip install semgrep' 또는 'docker pull semgrep/semgrep:1.95.0'을 실행하세요.");
      process.exit(1);
    }

    let targetFiles: string[] | undefined;
    if (!opts.all) {
      targetFiles = git(
        ["diff-tree", "--no-commit-id", "--name-only", "-r", "--root", "--diff-filter=d", commitHash],
        repoRoot
      )
        .split("\n")
        .filter(Boolean);
      if (targetFiles.length === 0) {
        console.log("변경된 파일이 없습니다 — --all로 전체 검사를 하려면 옵션을 추가하세요.");
        return;
      }
    }

    console.log(`[vibe-supervisor] semgrep 스캔 중... (${targetFiles ? `${targetFiles.length}개 파일, 증분` : "저장소 전체"})`);
    const actor = git(["config", "user.email"], repoRoot) || "unknown";
    const { findings, ruleset } = scanAndRecord(repoRoot, RULESET_PATH, commitHash, actor, targetFiles);

    console.log(
      `[vibe-supervisor] 스캔 완료 — 발견 ${findings.length}건 ` +
        `(룰셋 ${ruleset.version}, hash=${ruleset.hash.slice(0, 12)}…)`
    );
    for (const f of findings) {
      console.log(`  #${f.id} [${f.severity}] ${f.ruleId}  ${f.file}:${f.line}  — ${f.ismspClause}`);
    }
  });

program
  .command("approve <findingId>")
  .description("미승인 발견사항을 조치 완료·승인·예외 중 하나로 처리하고, 그 행위를 원장에 기록한다")
  .option("--fixed", "코드를 고쳐 해소했다고 기록한다 (무엇을 고쳤는지 --note로 반드시 남길 것)")
  .option("--exception", "고치지 않고 예외로 둔다고 기록한다 (사유를 --note로 반드시 남길 것)")
  .option("--note <text>", "조치 내용 / 승인·예외 사유")
  .action((findingIdArg, opts) => {
    const repoRoot = git(["rev-parse", "--show-toplevel"], process.cwd());
    const findingId = Number(findingIdArg);
    if (opts.fixed && opts.exception) {
      console.error("--fixed와 --exception은 함께 쓸 수 없습니다.");
      process.exit(1);
    }
    const status: FindingDecision = opts.fixed ? "fixed" : opts.exception ? "exception" : "approved";
    const note: string | null = opts.note?.trim() || null;

    if (status !== "approved" && !note) {
      console.error(
        `${DECISION_LABEL[status]}는 ${status === "fixed" ? "조치 내용" : "사유"}이 필수입니다 — --note "..."를 함께 입력하세요.`
      );
      process.exit(1);
    }

    const findingsStore = new FindingsStore(join(vsDir(repoRoot), "findings.db"));
    const target = findingsStore.get(findingId);
    if (!target) {
      findingsStore.close();
      console.error(`발견사항 #${findingIdArg}을(를) 찾을 수 없습니다.`);
      process.exit(1);
    }
    const actor = git(["config", "user.email"], repoRoot) || "unknown";

    // 원장에 먼저 남기고 DB를 바꾼다 — 반대 순서면 DB만 바뀌고 원장 기록이
    // 빠지는 경우가 생겨, verify가 그걸 "DB 직접 수정"으로 오인한다.
    const ledger = new Ledger(join(vsDir(repoRoot), "ledger.db"));
    ledger.append({
      eventType: status === "fixed" ? "fixed" : "approved",
      commitHash: git(["rev-parse", "HEAD"], repoRoot),
      actor,
      aiTool: null,
      originConfidence: "confirmed",
      fileHashes: [],
      payload: {
        kind: "approved",
        findingId,
        decision: status,
        note,
        ruleId: target.ruleId,
        file: target.file,
        line: target.line,
      },
    });
    ledger.close();

    findingsStore.approve(findingId, status, actor, note ?? undefined);
    findingsStore.close();

    console.log(`[vibe-supervisor] 발견사항 #${findingIdArg} — ${DECISION_LABEL[status]} 기록 완료 (${actor})`);
  });

program
  .command("report")
  .description("지금까지 쌓인 실제 원장·발견사항으로 감독 리포트를 생성한다")
  .option(
    "-o, --output <path>",
    "출력 파일 경로. 확장자가 .html이면 인쇄용 HTML(브라우저에서 PDF로 저장 가능)로 만든다",
    "vibe-supervisor-report.md"
  )
  .option("--tsa-ca <pem>", "TSA 신뢰 루트 인증서(PEM). 주면 앵커 검증에 인증서 체인까지 포함한다")
  .action(async (opts) => {
    const repoRoot = git(["rev-parse", "--show-toplevel"], process.cwd());
    requireLedger(repoRoot);
    const audit = await runAudit(repoRoot, readTrustedPem(opts.tsaCa));

    const repoName = (() => {
      try {
        // origin이 없는 저장소(로컬 전용 데모 등)가 흔해서, 실패를 정상 경로로
        // 취급하고 stderr도 흘리지 않는다 — git()은 에러를 그대로 보여주는
        // 용도라 여기선 안 씀.
        return execFileSync("git", ["remote", "get-url", "origin"], {
          cwd: repoRoot,
          encoding: "utf-8",
          stdio: ["ignore", "pipe", "ignore"],
        })
          .trim()
          .replace(/^.*[:/]([^/]+\/[^/]+?)(\.git)?$/, "$1");
      } catch {
        return repoRoot.split("/").pop() ?? repoRoot;
      }
    })();

    const timestamps = audit.entries.map((e) => e.timestamp).sort();

    // 룰셋 hash는 가장 최근 스캔 기준 — findings가 전부 같은 룰셋 파일에서
    // 나왔다는 전제(파일이 바뀌면 다음 scan부터 새 해시가 찍힌다).
    const rulesetHash = existsSync(RULESET_PATH)
      ? createHash("sha256").update(readFileSync(RULESET_PATH)).digest("hex")
      : "unknown";

    const report = generateReport(
      {
        repoName,
        periodStart: timestamps[0]?.slice(0, 10) ?? "-",
        periodEnd: timestamps[timestamps.length - 1]?.slice(0, 10) ?? "-",
        ruleset: { version: "ko-baseline-v1", hash: rulesetHash },
        findings: audit.findings,
        isSample: false,
      },
      audit
    );

    writeFileSync(opts.output, /\.html?$/i.test(opts.output) ? renderReportHtml(report) : report);
    console.log(
      `[vibe-supervisor] 리포트 생성 완료: ${opts.output} ` +
        `(실데이터 — 원장 ${audit.entries.length}건, 발견사항 ${audit.findings.length}건, 검증 ${audit.ok ? "통과" : "실패 항목 있음"})`
    );
  });

program.parseAsync();
