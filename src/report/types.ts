export type FindingSeverity = "critical" | "high" | "medium" | "low";

/** approved = 위험을 확인하고 받아들임, fixed = 코드를 고쳐 해소함, exception = 사유를 남기고 예외.
 * approved와 fixed를 나누는 이유: 리포트에서 "고쳤다"와 "그대로 두기로 했다"가 같은 "승인"으로
 * 보이면 심사원이 조치 여부를 판단할 수 없다. */
export type FindingStatus = "approved" | "fixed" | "exception" | "open";

export type FindingDecision = Exclude<FindingStatus, "open">;

export const DECISION_LABEL: Record<FindingDecision, string> = {
  approved: "승인",
  fixed: "조치 완료",
  exception: "예외 처리",
};

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
  /** true면 가짜 데모 데이터(심사원 인터뷰용), false면 실제 저장소에서 scan/approve로
   * 쌓인 실데이터. 리포트 상단 경고 문구가 이 값에 따라 달라진다 — 실데이터를
   * "샘플"이라고 잘못 표기하면 증빙으로서의 신뢰도 자체가 깨지므로 반드시 구분한다. */
  isSample: boolean;
}
