import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { Ledger } from "../ledger/db.js";
import type { LedgerEntry, ReviewDecision } from "../ledger/types.js";

export const REVIEW_DECISIONS = ["approved", "rejected", "pending"] as const;

export type ReviewErrorCode =
  | "invalid_decision"
  | "unknown_commit"
  | "no_generated_event"
  | "no_ledger";

export class ReviewError extends Error {
  readonly code: ReviewErrorCode;

  constructor(code: ReviewErrorCode, message: string) {
    super(message);
    this.name = "ReviewError";
    this.code = code;
  }
}

export interface ReviewInput {
  repoRoot: string;
  commit: string;
  decision: string;
  reviewer: string;
  note?: string | null;
}

export interface ReviewRecord {
  commitHash: string;
  aiTool: string | null;
  generatedAt: string;
  reviewer: string;
  decision: ReviewDecision;
  reviewedAt: string;
  note: string | null;
}

/**
 * 발견사항 승인 서명(src/signing/approval.ts)은 ApprovalClaim(findingId, ruleId,
 * file, line 등)과 namespace `vibe-supervisor-approval`에 묶여 있다. 커밋 검토
 * 기록에 그대로 쓰면 승인 서명을 검토 서명으로 재사용할 수 있어, 이번 변경에서는
 * 검토 서명을 넣지 않았다. 검토 서명도 필요하면 별도 claim 형식과 namespace가 필요하다.
 */
export function isReviewDecision(value: string): value is ReviewDecision {
  return (REVIEW_DECISIONS as readonly string[]).includes(value);
}

export function parseReviewDecision(value: string): ReviewDecision {
  if (isReviewDecision(value)) return value;
  throw new ReviewError(
    "invalid_decision",
    `결정 값이 올바르지 않습니다: ${value} (approved | rejected | pending)`
  );
}

export function normalizeNote(note: string | null | undefined): string | null {
  const trimmed = note?.trim() ?? "";
  return trimmed.length > 0 ? trimmed : null;
}

export function findGeneratedEvent(
  entries: LedgerEntry[],
  commitHash: string
): LedgerEntry | undefined {
  return entries.find((e) => e.eventType === "generated" && e.commitHash === commitHash);
}

export function resolveCommitHash(repoRoot: string, commit: string): string {
  try {
    return execFileSync("git", ["rev-parse", "--verify", "--end-of-options", `${commit}^{commit}`], {
      cwd: repoRoot,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch {
    throw new ReviewError("unknown_commit", `커밋을 찾을 수 없습니다: ${commit}`);
  }
}

export function buildReviewRecord(
  generated: LedgerEntry,
  input: { reviewer: string; decision: ReviewDecision; note: string | null; reviewedAt: string }
): ReviewRecord {
  return {
    commitHash: generated.commitHash,
    aiTool: generated.aiTool,
    generatedAt: generated.timestamp,
    reviewer: input.reviewer,
    decision: input.decision,
    reviewedAt: input.reviewedAt,
    note: input.note,
  };
}

function ledgerPath(repoRoot: string): string {
  const path = join(repoRoot, ".vibe-supervisor", "ledger.db");
  if (!existsSync(path)) {
    throw new ReviewError("no_ledger", "원장이 아직 없습니다 — 커밋을 먼저 해보세요.");
  }
  return path;
}

export function recordReview(input: ReviewInput): LedgerEntry {
  const decision = parseReviewDecision(input.decision);
  const reviewer = input.reviewer.trim();
  if (reviewer.length === 0) {
    throw new ReviewError("invalid_decision", "검토자(reviewer)가 비어 있습니다.");
  }
  const commitHash = resolveCommitHash(input.repoRoot, input.commit);
  const ledger = new Ledger(ledgerPath(input.repoRoot));
  try {
    const generated = findGeneratedEvent(ledger.all(), commitHash);
    if (!generated) {
      throw new ReviewError(
        "no_generated_event",
        `커밋 ${commitHash.slice(0, 8)}의 generated 기록이 원장에 없습니다.`
      );
    }
    const record = buildReviewRecord(generated, {
      reviewer,
      decision,
      note: normalizeNote(input.note),
      reviewedAt: new Date().toISOString(),
    });
    return ledger.append({
      eventType: "reviewed",
      commitHash,
      actor: reviewer,
      aiTool: record.aiTool,
      originConfidence: generated.originConfidence,
      fileHashes: [],
      payload: { kind: "reviewed", ...record },
    });
  } finally {
    ledger.close();
  }
}
