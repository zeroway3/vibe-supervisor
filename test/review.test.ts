import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ledger } from "../src/ledger/db.js";
import {
  buildReviewRecord,
  findGeneratedEvent,
  normalizeNote,
  parseReviewDecision,
  recordReview,
  ReviewError,
  resolveCommitHash,
} from "../src/review/record.js";
import { formatReviewResult, runReviewCommand } from "../src/review/cli.js";
import type { LedgerEntry, LedgerEntryInput } from "../src/ledger/types.js";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "vs-review-"));
}

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf-8" }).trim();
}

function initRepo(dir: string): void {
  git(["init", "-q"], dir);
  git(["config", "user.email", "reviewer@example.com"], dir);
  git(["config", "user.name", "reviewer"], dir);
  git(["config", "commit.gpgsign", "false"], dir);
}

function commitFile(dir: string, name: string, content: string): string {
  writeFileSync(join(dir, name), content);
  git(["add", name], dir);
  git(["commit", "-q", "-m", `add ${name}`], dir);
  return git(["rev-parse", "HEAD"], dir);
}

function generatedInput(commitHash: string, aiTool: string | null = "grok"): LedgerEntryInput {
  return {
    eventType: "generated",
    commitHash,
    actor: "dev@example.com",
    aiTool,
    originConfidence: aiTool ? "estimated" : "unknown",
    fileHashes: [{ path: "app.ts", hash: "ab".repeat(32) }],
    payload: {
      kind: "generated",
      aiRatio: null,
      originSource: aiTool ? "co-author-trailer" : "none",
    },
  };
}

function openLedger(repoRoot: string): Ledger {
  mkdirSync(join(repoRoot, ".vibe-supervisor"), { recursive: true });
  return new Ledger(join(repoRoot, ".vibe-supervisor", "ledger.db"));
}

function seedGenerated(repoRoot: string, commitHash: string, aiTool: string | null = "grok"): LedgerEntry {
  const ledger = openLedger(repoRoot);
  const entry = ledger.append(generatedInput(commitHash, aiTool));
  ledger.close();
  return entry;
}

test("결정 값을 정규화하고, 잘못된 값은 거절한다", () => {
  assert.equal(parseReviewDecision("approved"), "approved");
  assert.equal(parseReviewDecision("rejected"), "rejected");
  assert.equal(parseReviewDecision("pending"), "pending");
  assert.equal(normalizeNote("  사유  "), "사유");
  assert.equal(normalizeNote("   "), null);
  assert.equal(normalizeNote(undefined), null);
  try {
    parseReviewDecision("fixed");
    assert.fail("should throw");
  } catch (e) {
    assert.ok(e instanceof ReviewError);
    assert.equal(e.code, "invalid_decision");
  }
});

test("검토 기록 형식이 generated 이벤트에서 도구명과 생성 시각을 가져온다", () => {
  const generated: LedgerEntry = {
    id: 1,
    timestamp: "2026-11-21T00:00:00.000Z",
    prevHash: null,
    hash: "00",
    ...generatedInput("c".repeat(40), "grok"),
  };
  const record = buildReviewRecord(generated, {
    reviewer: "reviewer@example.com",
    decision: "approved",
    note: "확인함",
    reviewedAt: "2026-11-21T01:00:00.000Z",
  });
  assert.deepEqual(record, {
    commitHash: "c".repeat(40),
    aiTool: "grok",
    generatedAt: "2026-11-21T00:00:00.000Z",
    reviewer: "reviewer@example.com",
    decision: "approved",
    reviewedAt: "2026-11-21T01:00:00.000Z",
    note: "확인함",
  });
});

test("reviewed 이벤트를 추가한 뒤 체인 검증이 통과하고, 기존 행은 그대로다", () => {
  const dir = tmp();
  initRepo(dir);
  const commitHash = commitFile(dir, "app.ts", "console.log(1);\n");
  const generated = seedGenerated(dir, commitHash);
  const before = new Ledger(join(dir, ".vibe-supervisor", "ledger.db"));
  const prior = before.all().map((e) => ({ id: e.id, hash: e.hash, prevHash: e.prevHash }));
  assert.deepEqual(before.verify(), { ok: true, brokenAtId: null });
  before.close();

  const entry = recordReview({
    repoRoot: dir,
    commit: commitHash.slice(0, 8),
    decision: "approved",
    reviewer: "reviewer@example.com",
    note: "확인함",
  });

  assert.equal(entry.eventType, "reviewed");
  assert.equal(entry.commitHash, commitHash);
  assert.equal(entry.actor, "reviewer@example.com");
  assert.equal(entry.aiTool, "grok");
  assert.ok(entry.payload?.kind === "reviewed");
  if (entry.payload?.kind === "reviewed") {
    assert.equal(entry.payload.decision, "approved");
    assert.equal(entry.payload.generatedAt, generated.timestamp);
    assert.equal(entry.payload.reviewer, "reviewer@example.com");
    assert.equal(entry.payload.note, "확인함");
    assert.equal(entry.payload.aiTool, "grok");
    assert.equal(entry.payload.commitHash, commitHash);
    assert.match(entry.payload.reviewedAt, /^\d{4}-\d{2}-\d{2}T/);
  }

  const after = new Ledger(join(dir, ".vibe-supervisor", "ledger.db"));
  assert.deepEqual(after.verify(), { ok: true, brokenAtId: null });
  const rows = after.all();
  after.close();
  assert.equal(rows.length, 2);
  assert.deepEqual(
    rows.slice(0, 1).map((e) => ({ id: e.id, hash: e.hash, prevHash: e.prevHash })),
    prior
  );
});

test("reviewed 이벤트가 없는 구버전 원장도 그대로 검증된다", () => {
  const dir = tmp();
  initRepo(dir);
  const first = commitFile(dir, "a.ts", "a\n");
  const second = commitFile(dir, "b.ts", "b\n");
  const ledger = openLedger(dir);
  ledger.append(generatedInput(first, "cursor"));
  ledger.append(generatedInput(second, null));
  assert.deepEqual(ledger.verify(), { ok: true, brokenAtId: null });
  const hashes = ledger.all().map((e) => e.hash);
  ledger.close();

  const reopened = new Ledger(join(dir, ".vibe-supervisor", "ledger.db"));
  assert.deepEqual(reopened.verify(), { ok: true, brokenAtId: null });
  assert.deepEqual(reopened.all().map((e) => e.hash), hashes);
  assert.equal(findGeneratedEvent(reopened.all(), second)?.commitHash, second);
  reopened.close();
});

test("없는 커밋, generated 없는 커밋, 잘못된 결정은 거절한다", () => {
  const dir = tmp();
  initRepo(dir);
  const recorded = commitFile(dir, "a.ts", "a\n");
  const unrecorded = commitFile(dir, "b.ts", "b\n");
  seedGenerated(dir, recorded);

  try {
    recordReview({ repoRoot: dir, commit: "deadbeef", decision: "approved", reviewer: "r@x.com" });
    assert.fail("should throw");
  } catch (e) {
    assert.ok(e instanceof ReviewError);
    assert.equal(e.code, "unknown_commit");
  }

  try {
    recordReview({ repoRoot: dir, commit: unrecorded, decision: "rejected", reviewer: "r@x.com" });
    assert.fail("should throw");
  } catch (e) {
    assert.ok(e instanceof ReviewError);
    assert.equal(e.code, "no_generated_event");
  }

  try {
    recordReview({ repoRoot: dir, commit: recorded, decision: "fixed", reviewer: "r@x.com" });
    assert.fail("should throw");
  } catch (e) {
    assert.ok(e instanceof ReviewError);
    assert.equal(e.code, "invalid_decision");
  }

  const after = new Ledger(join(dir, ".vibe-supervisor", "ledger.db"));
  assert.equal(after.all().length, 1);
  assert.deepEqual(after.verify(), { ok: true, brokenAtId: null });
  after.close();
});

test("원장이 없으면 기록하지 않는다", () => {
  const dir = tmp();
  initRepo(dir);
  const commitHash = commitFile(dir, "a.ts", "a\n");
  try {
    recordReview({ repoRoot: dir, commit: commitHash, decision: "pending", reviewer: "r@x.com" });
    assert.fail("should throw");
  } catch (e) {
    assert.ok(e instanceof ReviewError);
    assert.equal(e.code, "no_ledger");
  }
});

test("저장소에 없는 커밋 참조는 resolveCommitHash가 거절한다", () => {
  const dir = tmp();
  initRepo(dir);
  commitFile(dir, "a.ts", "a\n");
  try {
    resolveCommitHash(dir, "1234567");
    assert.fail("should throw");
  } catch (e) {
    assert.ok(e instanceof ReviewError);
    assert.equal(e.code, "unknown_commit");
  }
});

test("CLI 핸들러는 git user.email을 검토자로 쓰고 결과를 포맷한다", () => {
  const dir = tmp();
  initRepo(dir);
  const commitHash = commitFile(dir, "app.ts", "x\n");
  seedGenerated(dir, commitHash, "cursor");
  const entry = runReviewCommand({ repoRoot: dir, commit: commitHash, decision: "pending", note: "보류" });
  assert.equal(entry.actor, "reviewer@example.com");
  assert.ok(entry.payload?.kind === "reviewed");
  if (entry.payload?.kind === "reviewed") {
    assert.equal(entry.payload.decision, "pending");
    assert.equal(entry.payload.note, "보류");
  }
  const message = formatReviewResult(entry);
  assert.match(message, /검토 기록 완료/);
  assert.match(message, /pending/);
  assert.match(message, /reviewer@example.com/);
});

test("이메일이 없으면 검토자를 unknown으로 남긴다", () => {
  const dir = tmp();
  initRepo(dir);
  const commitHash = commitFile(dir, "app.ts", "x\n");
  seedGenerated(dir, commitHash);
  git(["config", "user.email", "   "], dir);
  const entry = runReviewCommand({ repoRoot: dir, commit: commitHash, decision: "rejected" });
  assert.equal(entry.actor, "unknown");
});
