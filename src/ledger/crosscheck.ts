import type { LedgerEntry } from "./types.js";
import type { StoredFinding } from "../findings/store.js";

export interface CrossCheckIssue {
  findingId: number;
  message: string;
}

/**
 * findings.db는 일반 SQLite 테이블이라 누구나 고칠 수 있다. 그래서 "어떤 항목이
 * 탐지됐고 누가 어떻게 처리했는가"의 원본은 해시 체인에 들어간 payload로 두고,
 * findings.db가 그 원본과 어긋나는지를 여기서 대조한다.
 *
 * - 원장에 탐지 기록이 없는 발견사항 → 나중에 끼워 넣은 것
 * - 탐지 기록과 규칙/파일/라인이 다른 발견사항 → 바꿔치기
 * - 원장에 승인 기록이 없는데 승인/예외 상태인 것 → DB를 직접 고친 승인
 * - 마지막 승인 기록과 상태·처리자·사유가 다른 것 → 사후 수정
 * - 원장에는 탐지됐는데 DB에서 사라진 것 → 삭제
 *
 * payload가 없던 시절(구버전)의 원장 레코드는 대조 근거가 없으므로 건너뛴다 —
 * 대신 "근거 없음"을 숨기지 않고 unverifiable로 따로 센다.
 */
export function crossCheckFindings(
  entries: LedgerEntry[],
  findings: StoredFinding[]
): { issues: CrossCheckIssue[]; verified: number; unverifiable: number } {
  const detected = new Map<number, { ruleId: string; file: string; line: number }>();
  const lastApproval = new Map<number, { decision: string; note: string | null; actor: string }>();

  for (const e of entries) {
    if (e.payload?.kind === "detected") {
      for (const f of e.payload.findings) detected.set(f.findingId, f);
    } else if (e.payload?.kind === "approved") {
      lastApproval.set(e.payload.findingId, {
        decision: e.payload.decision,
        note: e.payload.note,
        actor: e.actor,
      });
    }
  }

  const issues: CrossCheckIssue[] = [];
  let verified = 0;
  let unverifiable = 0;

  // payload를 남기기 시작한 첫 탐지보다 앞선 발견사항은 구버전 스캔 결과 — 대조 불가.
  const firstTrackedId = detected.size > 0 ? Math.min(...detected.keys()) : Infinity;

  for (const f of findings) {
    const d = detected.get(f.id);
    if (!d) {
      if (f.id < firstTrackedId) {
        unverifiable++;
        continue;
      }
      issues.push({ findingId: f.id, message: "원장에 탐지 기록이 없는 발견사항입니다 (사후에 추가됐을 가능성)." });
      continue;
    }
    if (d.ruleId !== f.ruleId || d.file !== f.file || d.line !== f.line) {
      issues.push({
        findingId: f.id,
        message: `탐지 기록(${d.ruleId} ${d.file}:${d.line})과 현재 내용(${f.ruleId} ${f.file}:${f.line})이 다릅니다.`,
      });
      continue;
    }

    const a = lastApproval.get(f.id);
    if (!a) {
      if (f.status !== "open") {
        issues.push({
          findingId: f.id,
          message: `원장에 승인 기록이 없는데 상태가 '${f.status}'입니다 (DB를 직접 고쳤을 가능성).`,
        });
        continue;
      }
    } else if (a.decision !== f.status || a.actor !== (f.approvedBy ?? "") || a.note !== (f.approvalNote ?? null)) {
      issues.push({
        findingId: f.id,
        message:
          `원장의 마지막 처리 기록(${a.decision}, ${a.actor}, 사유: ${a.note ?? "없음"})과 ` +
          `현재 DB(${f.status}, ${f.approvedBy ?? "-"}, 사유: ${f.approvalNote ?? "없음"})가 다릅니다.`,
      });
      continue;
    }
    verified++;
  }

  const present = new Set(findings.map((f) => f.id));
  for (const id of detected.keys()) {
    if (!present.has(id)) {
      issues.push({ findingId: id, message: "원장에는 탐지 기록이 있는데 발견사항 DB에서 사라졌습니다 (삭제 의심)." });
    }
  }

  return { issues, verified, unverifiable };
}
