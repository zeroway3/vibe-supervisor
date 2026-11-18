import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ledger } from "../src/ledger/db.js";
import { auditCompleteness, checkCompleteness, type HistoryCommit } from "../src/ledger/completeness.js";

const EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const h = (c: string) => c.repeat(40).slice(0, 40);

function newLedger() {
  return new Ledger(join(mkdtempSync(join(tmpdir(), "vs-complete-")), "ledger.db"));
}

function recordCommit(ledger: Ledger, commit: string, files: Array<{ path: string; hash?: string }> = []) {
  ledger.append({
    eventType: "generated",
    commitHash: commit,
    actor: "dev@example.com",
    aiTool: null,
    originConfidence: "unknown",
    fileHashes: files.map((f) => ({ path: f.path, hash: f.hash ?? "abc" })),
    payload: { kind: "generated", aiRatio: null, originSource: "none" },
  });
}

function recordScan(ledger: Ledger, commit: string, files: string[]) {
  ledger.append({
    eventType: "detected",
    commitHash: commit,
    actor: "dev@example.com",
    aiTool: null,
    originConfidence: "confirmed",
    fileHashes: files.map((path) => ({ path, hash: "" })),
    payload: { kind: "detected", rulesetVersion: "v1", rulesetHash: "x", findings: [] },
  });
}

const commit = (c: string, parents: string[] = [h("0")]): HistoryCommit => ({
  hash: h(c),
  parents,
  author: "dev",
  date: "2026-11-18T10:00:00+09:00",
  subject: `commit ${c}`,
});

test("원장에 기록이 없는 일반 커밋은 누락으로 잡힌다", () => {
  const ledger = newLedger();
  recordCommit(ledger, h("a"));
  recordCommit(ledger, h("c"));
  const history = [commit("c"), commit("b"), commit("a")];
  const r = checkCompleteness(history, new Set(history.map((x) => x.hash)), ledger.all(), h("a"));
  assert.deepEqual(r.missing.map((m) => m.hash), [h("b")]);
  assert.equal(r.checked, 3);
  assert.equal(r.recorded, 2);
  ledger.close();
});

test("병합 커밋은 기록이 없어도 누락이 아니라 '확인 필요'로 따로 센다", () => {
  const ledger = newLedger();
  recordCommit(ledger, h("a"));
  const merge = commit("m", [h("a"), h("b")]);
  const history = [merge, commit("a")];
  const r = checkCompleteness(history, new Set(history.map((x) => x.hash)), ledger.all(), h("a"));
  assert.equal(r.missing.length, 0);
  assert.deepEqual(r.unrecordedMerges.map((m) => m.hash), [h("m")]);
  ledger.close();
});

test("원장에는 있지만 이력에서 사라진 커밋(amend·rebase)은 따로 드러난다", () => {
  const ledger = newLedger();
  recordCommit(ledger, h("a"));
  recordCommit(ledger, h("x")); // amend 전 해시
  const history = [commit("a")];
  const r = checkCompleteness(history, new Set([h("a")]), ledger.all(), h("a"));
  assert.deepEqual(r.orphaned.map((o) => o.commitHash), [h("x")]);
  assert.equal(r.missing.length, 0);
  ledger.close();
});

test("검사 기록: 커밋 시점 검사 / 이후 검사 / 검사 없음을 구분하고, 삭제 파일은 대상에서 뺀다", () => {
  const ledger = newLedger();
  recordCommit(ledger, h("a"), [{ path: "A.java" }, { path: "gone.java", hash: EMPTY }]);
  recordScan(ledger, h("a"), ["A.java"]); // 커밋 시점 검사
  recordCommit(ledger, h("b"), [{ path: "B.java" }]); // 건너뜀 → 나중에 전체 검사
  recordCommit(ledger, h("c"), [{ path: "C.java" }]); // 끝까지 검사 없음
  recordScan(ledger, h("c"), ["A.java", "B.java"]); // scan --all 이 C.java는 못 봄

  const history = [commit("c"), commit("b"), commit("a")];
  const r = checkCompleteness(history, new Set(history.map((x) => x.hash)), ledger.all(), h("a"));
  assert.equal(r.lateScanned, 1);
  assert.deepEqual(r.scanGaps, [{ commitHash: h("c"), files: ["C.java"] }]);
  ledger.close();
});

test("이전 커밋에 대한 검사 기록은 그보다 뒤에 만든 커밋의 근거가 되지 않는다", () => {
  const ledger = newLedger();
  recordScan(ledger, h("z"), ["A.java"]); // 커밋 기록보다 먼저 있던 검사
  recordCommit(ledger, h("a"), [{ path: "A.java" }]);
  const history = [commit("a")];
  const r = checkCompleteness(history, new Set([h("a")]), ledger.all(), h("a"));
  assert.deepEqual(r.scanGaps, [{ commitHash: h("a"), files: ["A.java"] }]);
  ledger.close();
});

// ── 실제 git 저장소 ──────────────────────────────────

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf-8" }).trim();
}

function tmpRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), "vs-complete-repo-"));
  git(["init", "-q"], dir);
  git(["config", "user.email", "dev@example.com"], dir);
  git(["config", "user.name", "dev"], dir);
  git(["config", "commit.gpgsign", "false"], dir);
  return dir;
}

function commitFile(dir: string, name: string): string {
  writeFileSync(join(dir, name), name);
  git(["add", name], dir);
  git(["commit", "-q", "-m", `add ${name}`], dir);
  return git(["rev-parse", "HEAD"], dir);
}

test("실제 git 이력: 도입 전 커밋은 제외하고, 훅을 거치지 않은 커밋만 누락으로 잡는다", () => {
  const dir = tmpRepo();
  commitFile(dir, "before-install.txt"); // 도구 도입 전 — 대상 아님
  const c1 = commitFile(dir, "a.txt");
  const c2 = commitFile(dir, "b.txt");
  const c3 = commitFile(dir, "c.txt"); // 훅 없이 만든 커밋이라고 가정

  const ledger = newLedger();
  recordCommit(ledger, c1);
  recordCommit(ledger, c2);
  const r = auditCompleteness(dir, ledger.all());
  ledger.close();

  assert.equal(r.baseline, c1);
  assert.equal(r.checked, 3);
  assert.deepEqual(r.missing.map((m) => m.hash), [c3]);
  assert.equal(r.missing[0].subject, "add c.txt");
});

test("실제 git 이력: --since로 기준 커밋을 지정하면 그 커밋부터 대조한다", () => {
  const dir = tmpRepo();
  const c0 = commitFile(dir, "a.txt");
  const c1 = commitFile(dir, "b.txt");

  const ledger = newLedger();
  recordCommit(ledger, c1);
  const r = auditCompleteness(dir, ledger.all(), c0);
  ledger.close();

  assert.equal(r.baseline, c0);
  assert.deepEqual(r.missing.map((m) => m.hash), [c0]);
});

test("실제 git 이력: 원장 기록이 이력에 하나도 없으면 확인 범위 없음으로 끝난다", () => {
  const dir = tmpRepo();
  commitFile(dir, "a.txt");
  const ledger = newLedger();
  recordCommit(ledger, h("f"));
  const r = auditCompleteness(dir, ledger.all());
  ledger.close();

  assert.equal(r.baseline, null);
  assert.equal(r.missing.length, 0);
  assert.deepEqual(r.orphaned.map((o) => o.commitHash), [h("f")]);
});
