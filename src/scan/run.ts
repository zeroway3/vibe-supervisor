import { join } from "node:path";
import { Ledger } from "../ledger/db.js";
import { FindingsStore, type StoredFinding } from "../findings/store.js";
import { resolveSemgrepRunner, runSemgrepScan } from "./semgrep.js";
import type { RulesetInfo } from "../report/types.js";

export function isSemgrepAvailable(): boolean {
  return resolveSemgrepRunner() !== null;
}

/**
 * 스캔하고, 결과를 findings.db에 저장하고, 무엇을 찾았는지를 원장에 고정한다.
 * CLI의 scan과 post-commit 훅(커밋 시점 증분 검사)이 같은 경로를 쓴다.
 */
export function scanAndRecord(
  repoRoot: string,
  rulesetPath: string,
  commitHash: string,
  actor: string,
  targetFiles?: string[]
): { findings: StoredFinding[]; ruleset: RulesetInfo } {
  const { findings, ruleset } = runSemgrepScan(repoRoot, rulesetPath, targetFiles);

  const findingsStore = new FindingsStore(join(repoRoot, ".vibe-supervisor", "findings.db"));
  const ids = findingsStore.saveAll(commitHash, findings);
  const stored = findingsStore.all().filter((f) => ids.includes(f.id));
  findingsStore.close();

  const ledger = new Ledger(join(repoRoot, ".vibe-supervisor", "ledger.db"));
  ledger.append({
    eventType: "detected",
    commitHash,
    actor,
    aiTool: null,
    originConfidence: "confirmed",
    fileHashes: (targetFiles ?? []).map((path) => ({ path, hash: "" })), // 코드 본문 저장 안 함 — 어떤 파일을 스캔했는지만 기록
    payload: {
      kind: "detected",
      rulesetVersion: ruleset.version,
      rulesetHash: ruleset.hash,
      findings: stored.map((f) => ({ findingId: f.id, ruleId: f.ruleId, file: f.file, line: f.line })),
    },
  });
  ledger.close();

  return { findings: stored, ruleset };
}
