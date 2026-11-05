export type OriginConfidence = "confirmed" | "estimated" | "unknown";

export type LedgerEventType = "generated" | "detected" | "fixed" | "approved";

export interface FileHash {
  path: string;
  /** sha256 of the file's full content at this commit. MVP uses whole-file
   * hashing; byte-range hashing per AI-generated hunk is a later refinement
   * once origin tracking moves past the commit-trailer method. */
  hash: string;
}

/** 이벤트별 상세 내용. 해시 계산에 포함되므로, 여기 들어간 값은 원장 밖
 * (findings.db 등)에서 고쳐도 원장과 대조해 잡아낼 수 있다. 코드 본문은
 * 절대 넣지 않는다 — 규칙 ID·파일 경로·라인·사유 같은 메타데이터만. */
export type LedgerPayload =
  | {
      kind: "generated";
      /** AI-Generated 트레일러의 ratio (0~1). 없으면 null. */
      aiRatio: number | null;
      /** 출처를 판정한 근거 — "ai-generated-trailer" | "co-author-trailer" | "none" */
      originSource: string;
    }
  | {
      kind: "detected";
      rulesetVersion: string;
      rulesetHash: string;
      /** 이 스캔에서 저장된 발견사항. findings.db의 id와 내용을 함께 고정한다. */
      findings: Array<{ findingId: number; ruleId: string; file: string; line: number }>;
    }
  | {
      kind: "approved";
      findingId: number;
      decision: "approved" | "fixed" | "exception";
      note: string | null;
      /** 승인 시점 findings.db에 있던 대상 항목 — 나중에 다른 항목으로 바꿔치기한 걸 잡는다. */
      ruleId: string;
      file: string;
      line: number;
    };

export interface LedgerEntryInput {
  eventType: LedgerEventType;
  commitHash: string;
  actor: string;
  aiTool: string | null;
  originConfidence: OriginConfidence;
  fileHashes: FileHash[];
  payload?: LedgerPayload;
}

export interface LedgerEntry extends LedgerEntryInput {
  id: number;
  timestamp: string;
  prevHash: string | null;
  hash: string;
}
