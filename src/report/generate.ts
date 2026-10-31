import type { LedgerEntry } from "../ledger/types.js";
import type { ReportInput, Finding } from "./types.js";

function pct(n: number, total: number): string {
  if (total === 0) return "0%";
  return `${((n / total) * 100).toFixed(1)}%`;
}

function confidenceBreakdown(entries: LedgerEntry[]) {
  const total = entries.length;
  const confirmed = entries.filter((e) => e.originConfidence === "confirmed").length;
  const estimated = entries.filter((e) => e.originConfidence === "estimated").length;
  const unknown = entries.filter((e) => e.originConfidence === "unknown").length;
  return { total, confirmed, estimated, unknown };
}

function findingsTable(findings: Finding[]): string {
  if (findings.length === 0) return "_이 기간 동안 탐지된 항목이 없습니다._";
  const header = "| 규칙 ID | 심각도 | 파일:라인 | ISMS-P 조항 | 상태 | 처리자/사유 |\n|---|---|---|---|---|---|";
  const rows = findings.map((f) => {
    const statusLabel =
      f.status === "approved" ? "승인" : f.status === "exception" ? "예외 처리" : "⚠ 미승인";
    const actor = f.approvedBy ? `${f.approvedBy}${f.approvalNote ? ` — ${f.approvalNote}` : ""}` : "-";
    return `| ${f.ruleId} | ${f.severity} | ${f.file}:${f.line} | ${f.ismspClause} | ${statusLabel} | ${actor} |`;
  });
  return [header, ...rows].join("\n");
}

export function generateReport(
  input: ReportInput,
  ledgerEntries: LedgerEntry[],
  chainIntegrity: { ok: boolean; brokenAtId: number | null }
): string {
  const { total, confirmed, estimated, unknown } = confidenceBreakdown(ledgerEntries);
  const unapproved = input.findings.filter((f) => f.status === "open");

  const warningBlock = input.isSample
    ? `> ⚠ 이 리포트는 **데모용 샘플 데이터**로 생성되었습니다. 실제 고객 저장소의
> 실데이터가 아니며, ISMS-P 조항 매핑도 재검증이 필요한 추정값입니다.
> 심사 자료로서의 수용 가능성을 확인하기 위한 형식 검토용 샘플입니다.`
    : `> ⚠ 이 리포트는 이 저장소의 **실제 원장·스캔 기록**으로 생성되었습니다.
> 다만 ISMS-P 조항 매핑은 아직 현직 심사원 검증을 거치지 않은 추정값입니다 —
> 리포트 본문의 "[확인 필요]" 표기가 붙은 항목은 심사 근거로 그대로 인용하지 마세요.`;

  return `# 바이브 슈퍼바이저 — 개발보안 감독 리포트${input.isSample ? " (샘플)" : ""}

${warningBlock}

| 항목 | 값 |
|---|---|
| 대상 저장소 | ${input.repoName} |
| 집계 기간 | ${input.periodStart} ~ ${input.periodEnd} |
| 룰셋 버전 | ${input.ruleset.version} (hash: \`${input.ruleset.hash.slice(0, 16)}…\`) |
| 생성 시각 | ${new Date().toISOString()} |
| 원장 무결성 | ${chainIntegrity.ok ? "✅ 정상 (변조 흔적 없음)" : `❌ 깨짐 — id=${chainIntegrity.brokenAtId} 이후`} |

## 1. 출처 추적 요약

이 기간 동안 기록된 커밋 ${total}건의 AI 생성 출처 신뢰도 분포입니다.

| 신뢰도 | 건수 | 비율 |
|---|---|---|
| 확정 (confirmed) | ${confirmed} | ${pct(confirmed, total)} |
| 추정 (estimated) | ${estimated} | ${pct(estimated, total)} |
| 미상 (unknown) | ${unknown} | ${pct(unknown, total)} |

> 도구가 판단하지 못한 부분("미상")을 숨기지 않고 그대로 표기합니다 — 정확도를
> 과장하지 않는 것이 증빙 자료로서는 더 신뢰할 수 있다는 판단입니다.

## 2. 탐지 및 조치 현황

${findingsTable(input.findings)}

**미승인 항목: ${unapproved.length}건** ${unapproved.length > 0 ? "— 담당자 확인이 필요합니다." : ""}

## 3. 재현 가능성

이 리포트는 룰셋 버전 \`${input.ruleset.version}\`(hash \`${input.ruleset.hash.slice(0, 16)}…\`)로
고정된 상태에서 생성되었습니다. 같은 커밋 범위에 같은 룰셋 버전으로 다시
생성해도 동일한 결과가 나옵니다 — 생성 시점에 따라 결과가 달라지는 LLM 단독
도구와의 핵심 차이점입니다.

## 4. 감독 원장 상세 (부록)

| # | 커밋 | 시각 | 출처 | 파일 수 | 레코드 해시 |
|---|---|---|---|---|---|
${ledgerEntries
  .map(
    (e) =>
      `| ${e.id} | ${e.commitHash.slice(0, 8)} | ${e.timestamp} | ${e.originConfidence}${e.aiTool ? `(${e.aiTool})` : ""} | ${e.fileHashes.length} | \`${e.hash.slice(0, 16)}…\` |`
  )
  .join("\n")}
`;
}
