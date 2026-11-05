import type { LedgerEntry } from "./types.js";

export interface RescanEvidence {
  /** 해당 파일을 다시 검사했는데 같은 규칙이 더는 나오지 않은 첫 검사 레코드 */
  ledgerEntryId: number;
  commitHash: string;
  timestamp: string;
}

/**
 * "고쳤다"는 주장을 원장 기록만으로 뒷받침한다. 발견사항이 탐지된 뒤, 같은 파일을
 * 다시 검사한 detected 레코드에서 같은 규칙이 그 파일에 더는 나오지 않았다면 그 검사를
 * 재검사 근거로 돌려준다.
 *
 * - 어떤 파일을 검사했는지는 detected 레코드의 fileHashes(경로만, 해시는 빈 값)로 안다.
 *   전체 검사(scan --all)는 대상 파일 목록을 남기지 않으므로 근거로 쓰지 않는다 —
 *   "검사했는지 모르는" 걸 "사라졌다"로 판정하지 않기 위해서.
 * - 라인은 수정으로 밀리기 쉬우므로 규칙+파일로만 비교한다.
 * - 이 값은 원장(해시 체인)에서 계산되므로 findings.db를 고쳐도 바뀌지 않는다.
 */
export function rescanEvidence(
  entries: LedgerEntry[],
  findings: Array<{ id: number; ruleId: string; file: string }>
): Map<number, RescanEvidence> {
  const detectedAt = new Map<number, number>(); // findingId → 탐지 레코드 id
  for (const e of entries) {
    if (e.payload?.kind !== "detected") continue;
    for (const f of e.payload.findings) detectedAt.set(f.findingId, e.id);
  }

  const result = new Map<number, RescanEvidence>();
  for (const f of findings) {
    const from = detectedAt.get(f.id);
    if (from === undefined) continue;
    // 가장 최근 검사 기준으로 판정한다 — 사라졌다가 다시 나왔으면 근거 없음.
    let ev: RescanEvidence | undefined;
    for (const e of entries) {
      if (e.id <= from || e.payload?.kind !== "detected") continue;
      if (!e.fileHashes.some((h) => h.path === f.file)) continue;
      const stillThere = e.payload.findings.some((x) => x.ruleId === f.ruleId && x.file === f.file);
      if (stillThere) ev = undefined;
      else ev ??= { ledgerEntryId: e.id, commitHash: e.commitHash, timestamp: e.timestamp };
    }
    if (ev) result.set(f.id, ev);
  }
  return result;
}
