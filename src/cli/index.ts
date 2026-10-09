#!/usr/bin/env node
import { Command } from "commander";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Ledger } from "../ledger/db.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const HOOK_SCRIPT = join(__dirname, "..", "hooks", "post-commit.js");

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

program.parse();
