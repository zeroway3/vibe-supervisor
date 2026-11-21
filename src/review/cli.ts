import { execFileSync } from "node:child_process";
import { recordReview, ReviewError, type ReviewInput } from "./record.js";
import type { LedgerEntry } from "../ledger/types.js";

export interface ReviewCommandArgs {
  repoRoot: string;
  commit: string;
  decision: string;
  note?: string;
}

function gitEmail(repoRoot: string): string {
  try {
    const email = execFileSync("git", ["config", "user.email"], {
      cwd: repoRoot,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
    return email.length > 0 ? email : "unknown";
  } catch {
    return "unknown";
  }
}

export function runReviewCommand(args: ReviewCommandArgs): LedgerEntry {
  const input: ReviewInput = {
    repoRoot: args.repoRoot,
    commit: args.commit,
    decision: args.decision,
    reviewer: gitEmail(args.repoRoot),
    note: args.note,
  };
  return recordReview(input);
}

export function formatReviewResult(entry: LedgerEntry): string {
  const payload = entry.payload;
  const decision = payload?.kind === "reviewed" ? payload.decision : entry.eventType;
  const note = payload?.kind === "reviewed" && payload.note ? `, 사유: ${payload.note}` : "";
  return (
    `[vibe-supervisor] 커밋 ${entry.commitHash.slice(0, 8)} 검토 기록 완료 — ` +
    `결정: ${decision}, 검토자: ${entry.actor}, 원장 #${entry.id}${note}`
  );
}

export { ReviewError };
