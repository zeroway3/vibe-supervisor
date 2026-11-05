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
 *
 * targetFiles와 recordFiles를 분리한 이유: 전체 검사(`scan --all`)는 semgrep
 * 자신의 gitignore-aware 디렉터리 순회에 맡기는 게(targetFiles=undefined →
 * "." 전달) 더 정확하지만, 그러면 원장에 "어떤 파일을 봤는지"가 안 남아서
 * rescanEvidence가 전체 검사를 재검사 근거로 못 쓴다(rescan.ts 참고). 그래서
 * 실제 스캔 대상(targetFiles)과 원장에 남길 파일 목록(recordFiles)을 따로
 * 받는다 — 증분 스캔은 둘이 같고(recordFiles 생략 시 targetFiles로 폴백),
 * 전체 검사는 targetFiles=undefined(semgrep이 "."을 봄) + recordFiles=git
 * ls-files 결과(원장에 남을 실제 목록)로 호출된다.
 */
export function scanAndRecord(
  repoRoot: string,
  rulesetPath: string,
  commitHash: string,
  actor: string,
  targetFiles?: string[],
  recordFiles?: string[]
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
    // 코드 본문 저장 안 함 — 어떤 파일을 스캔했는지만 기록
    fileHashes: (recordFiles ?? targetFiles ?? []).map((path) => ({ path, hash: "" })),
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
