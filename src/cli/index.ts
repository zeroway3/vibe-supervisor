#!/usr/bin/env node
import { Command } from "commander";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Ledger } from "../ledger/db.js";
import { FindingsStore } from "../findings/store.js";
import { runSemgrepScan } from "../scan/semgrep.js";
import { generateReport } from "../report/generate.js";

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

    writeFileSync(hookPath, `#!/bin/sh\nnode "${HOOK_SCRIPT}"\n`);
    chmodSync(hookPath, 0o755);
    console.log(`post-commit 훅을 설치했습니다: ${hookPath}`);
  });

program
  .command("verify")
  .description("감독 원장의 해시 체인 무결성을 검증한다")
  .action(() => {
    const repoRoot = git(["rev-parse", "--show-toplevel"], process.cwd());
    const dbPath = join(repoRoot, ".vibe-supervisor", "ledger.db");
    if (!existsSync(dbPath)) {
      console.error("원장이 아직 없습니다 — 커밋을 먼저 해보세요.");
      process.exit(1);
    }
    const ledger = new Ledger(dbPath);
    const result = ledger.verify();
    ledger.close();

    if (result.ok) {
      console.log("체인 무결성 OK — 변조 흔적 없음.");
    } else {
      console.error(`체인 깨짐 — id=${result.brokenAtId} 이후 기록이 원래 해시와 안 맞습니다.`);
      process.exit(1);
    }
  });

program
  .command("log")
  .description("원장에 쌓인 기록을 최근순으로 보여준다")
  .action(() => {
    const repoRoot = git(["rev-parse", "--show-toplevel"], process.cwd());
    const dbPath = join(repoRoot, ".vibe-supervisor", "ledger.db");
    if (!existsSync(dbPath)) {
      console.error("원장이 아직 없습니다 — 커밋을 먼저 해보세요.");
      process.exit(1);
    }
    const ledger = new Ledger(dbPath);
    const entries = ledger.all();
    ledger.close();

    for (const e of entries.slice().reverse()) {
      console.log(
        `#${e.id}  ${e.timestamp}  ${e.commitHash.slice(0, 8)}  ` +
          `${e.originConfidence}${e.aiTool ? `(${e.aiTool})` : ""}  ` +
          `파일 ${e.fileHashes.length}개  hash=${e.hash.slice(0, 12)}…`
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

    let targetFiles: string[] | undefined;
    if (!opts.all) {
      targetFiles = git(
        ["diff-tree", "--no-commit-id", "--name-only", "-r", "--root", commitHash],
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
    const { findings, ruleset } = runSemgrepScan(repoRoot, RULESET_PATH, targetFiles);

    const findingsStore = new FindingsStore(join(vsDir(repoRoot), "findings.db"));
    findingsStore.saveAll(commitHash, findings);
    findingsStore.close();

    const ledger = new Ledger(join(vsDir(repoRoot), "ledger.db"));
    ledger.append({
      eventType: "detected",
      commitHash,
      actor: git(["config", "user.email"], repoRoot) || "unknown",
      aiTool: null,
      originConfidence: "confirmed",
      fileHashes: (targetFiles ?? []).map((path) => ({ path, hash: "" })), // 코드 본문 저장 안 함 — 어떤 파일을 스캔했는지만 기록
    });
    ledger.close();

    console.log(
      `[vibe-supervisor] 스캔 완료 — 발견 ${findings.length}건 ` +
        `(룰셋 ${ruleset.version}, hash=${ruleset.hash.slice(0, 12)}…)`
    );
    for (const f of findings) {
      console.log(`  [${f.severity}] ${f.ruleId}  ${f.file}:${f.line}  — ${f.ismspClause}`);
    }
  });

program
  .command("approve <findingId>")
  .description("미승인 발견사항을 승인하거나 예외 처리하고, 그 행위를 원장에 기록한다")
  .option("--exception", "승인이 아니라 예외 처리로 기록한다 (사유를 --note로 반드시 남길 것)")
  .option("--note <text>", "승인/예외 사유")
  .action((findingIdArg, opts) => {
    const repoRoot = git(["rev-parse", "--show-toplevel"], process.cwd());
    const findingsStore = new FindingsStore(join(vsDir(repoRoot), "findings.db"));
    const actor = git(["config", "user.email"], repoRoot) || "unknown";
    const status: "approved" | "exception" = opts.exception ? "exception" : "approved";

    const ok = findingsStore.approve(Number(findingIdArg), status, actor, opts.note);
    findingsStore.close();

    if (!ok) {
      console.error(`발견사항 #${findingIdArg}을(를) 찾을 수 없습니다.`);
      process.exit(1);
    }

    const ledger = new Ledger(join(vsDir(repoRoot), "ledger.db"));
    ledger.append({
      eventType: "approved",
      commitHash: git(["rev-parse", "HEAD"], repoRoot),
      actor,
      aiTool: null,
      originConfidence: "confirmed",
      fileHashes: [],
    });
    ledger.close();

    console.log(`[vibe-supervisor] 발견사항 #${findingIdArg} — ${status === "approved" ? "승인" : "예외 처리"} 기록 완료 (${actor})`);
  });

program
  .command("report")
  .description("지금까지 쌓인 실제 원장·발견사항으로 감독 리포트를 생성한다")
  .option("-o, --output <path>", "출력 파일 경로", "vibe-supervisor-report.md")
  .action((opts) => {
    const repoRoot = git(["rev-parse", "--show-toplevel"], process.cwd());
    const ledgerPath = join(vsDir(repoRoot), "ledger.db");
    const findingsPath = join(vsDir(repoRoot), "findings.db");

    if (!existsSync(ledgerPath)) {
      console.error("원장이 아직 없습니다 — 커밋을 먼저 해보세요.");
      process.exit(1);
    }

    const ledger = new Ledger(ledgerPath);
    const entries = ledger.all();
    const integrity = ledger.verify();
    ledger.close();

    let findings: ReturnType<FindingsStore["all"]> = [];
    if (existsSync(findingsPath)) {
      const findingsStore = new FindingsStore(findingsPath);
      findings = findingsStore.all();
      findingsStore.close();
    }

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

    const timestamps = entries.map((e) => e.timestamp).sort();

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
        findings,
        isSample: false,
      },
      entries,
      integrity
    );

    writeFileSync(opts.output, report);
    console.log(`[vibe-supervisor] 리포트 생성 완료: ${opts.output} (실데이터 — 원장 ${entries.length}건, 발견사항 ${findings.length}건)`);
  });

program.parse();
