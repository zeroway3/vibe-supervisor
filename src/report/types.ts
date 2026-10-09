export type FindingSeverity = "critical" | "high" | "medium" | "low";

export type FindingStatus = "approved" | "exception" | "open";

export interface Finding {
  ruleId: string;
  severity: FindingSeverity;
  file: string;
  line: number;
  message: string;
  /** ISMS-P 인증기준 조항 번호. 실제 심사에 쓰려면 현재 유효한 인증기준
   * 고시(2023년 개정판 기준)와 대조해 재확인이 필요 — 여기 값은 룰 작성
   * 시점의 추정 매핑이며 법적/심사 근거로 그대로 인용하면 안 된다. */
  ismspClause: string;
  status: FindingStatus;
  approvedBy?: string;
  approvalNote?: string;
}

export interface RulesetInfo {
  version: string;
  hash: string;
}

export interface ReportInput {
  repoName: string;
  periodStart: string;
  periodEnd: string;
  ruleset: RulesetInfo;
  findings: Finding[];
}
