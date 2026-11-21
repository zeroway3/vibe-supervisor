import type { ApprovalSignature } from "../signing/approval.js";

export type OriginConfidence = "confirmed" | "estimated" | "unknown";

export type ReviewDecision = "approved" | "rejected" | "pending";

export type LedgerEventType = "generated" | "detected" | "fixed" | "approved" | "reviewed";

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
      /** 이 커밋이 GPG/SSH로 서명됐는지. actor(git 이메일)는 누구나 자유롭게
       * 설정할 수 있어 신원 근거로 약하다 — 서명이 있으면 "이 키의 소유자가
       * 만든 커밋"이라는 더 강한 근거가 된다. 선택 필드라 이 필드가 생기기
       * 전 원장도 그대로 검증된다. */
      signature?: { status: string; signer: string | null };
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
      /** 승인자의 SSH 서명. actor(git 이메일)는 자기신고라, 서명이 있으면
       * "이 키 소유자가 이 내용으로 승인했다"는 근거가 된다. 선택 필드라
       * 서명 없는 승인·구버전 원장도 그대로 검증된다. */
      signature?: ApprovalSignature;
    }
  | {
      kind: "reviewed";
      /** 검토 대상 커밋. LedgerEntry.commitHash와 같다. */
      commitHash: string;
      aiTool: string | null;
      /** 대상 커밋의 generated 이벤트가 원장에 기록된 시각. */
      generatedAt: string;
      reviewer: string;
      decision: ReviewDecision;
      reviewedAt: string;
      note: string | null;
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
