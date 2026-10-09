#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { Ledger } from "../ledger/db.js";
import { parseAiTrailer } from "../trailer/parse.js";
import type { FileHash } from "../ledger/types.js";

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf-8" }).trim();
}

function main() {
  const repoRoot = git(["rev-parse", "--show-toplevel"], process.cwd());
  const commitHash = git(["rev-parse", "HEAD"], repoRoot);
  const commitMessage = git(["log", "-1", "--pretty=%B", commitHash], repoRoot);
  const actor = git(["config", "user.email"], repoRoot) || "unknown";

  // --root: 부모가 없는 첫 커밋(root commit)도 빈 트리와 비교해 변경 파일로
  // 잡아낸다. 이게 없으면 저장소의 첫 커밋이 항상 "파일 0개"로 기록된다.
  const changedFiles = git(
    ["diff-tree", "--no-commit-id", "--name-only", "-r", "--root", commitHash],
    repoRoot
  )
    .split("\n")
    .filter(Boolean);

  // MVP: 파일 전체 내용의 sha256. 실제 AI 생성 구간(byte range)만 잡아내는
  // 건 출처 추적이 트레일러 단계를 넘어선 뒤에 할 일 — 지금은 "이 커밋에서
  // 이 파일이 이 상태였다"는 사실만 변조 불가능하게 남기는 게 목표다.
  const fileHashes: FileHash[] = changedFiles.map((path) => {
    let content: string;
    try {
      content = git(["show", `${commitHash}:${path}`], repoRoot);
    } catch {
      // 삭제된 파일 등 HEAD에 내용이 없는 경우
      content = "";
    }
    return { path, hash: createHash("sha256").update(content).digest("hex") };
  });

  const { aiTool, confidence } = parseAiTrailer(commitMessage);

  const dbPath = join(repoRoot, ".vibe-supervisor", "ledger.db");
  const ledger = new Ledger(dbPath);
  const entry = ledger.append({
    eventType: "generated",
    commitHash,
    actor,
    aiTool,
    originConfidence: confidence,
    fileHashes,
  });
  ledger.close();

  console.log(
    `[vibe-supervisor] 커밋 ${commitHash.slice(0, 8)} 기록 완료 — ` +
      `출처: ${confidence}${aiTool ? ` (${aiTool})` : ""}, 파일 ${fileHashes.length}개, 원장 #${entry.id}`
  );
}

main();
