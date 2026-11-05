import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getCommitSignature } from "../src/trailer/signature.js";

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf-8" }).trim();
}

function tmpRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), "vs-sig-test-"));
  git(["init", "-q"], dir);
  git(["config", "user.email", "dev@example.com"], dir);
  git(["config", "user.name", "dev"], dir);
  // 테스트 환경에 GPG 서명 키가 없을 수 있으니 서명은 절대 켜지 않는다 —
  // 이 테스트는 "미서명 커밋을 정직하게 none으로 읽는가"를 본다.
  git(["config", "commit.gpgsign", "false"], dir);
  return dir;
}

test("서명하지 않은 커밋은 status=none, signer=null로 정직하게 읽힌다", () => {
  const dir = tmpRepo();
  writeFileSync(join(dir, "a.txt"), "a");
  git(["add", "a.txt"], dir);
  git(["commit", "-q", "-m", "feat: a"], dir);
  const commitHash = git(["rev-parse", "HEAD"], dir);

  const sig = getCommitSignature(dir, commitHash);
  assert.equal(sig.status, "none");
  assert.equal(sig.signer, null);
});

test("존재하지 않는 커밋 해시를 줘도 던지지 않고 none으로 폴백한다", () => {
  const dir = tmpRepo();
  // 레포는 만들었지만 커밋이 하나도 없는 상태 — git log가 실패하는 경로를 본다.
  const sig = getCommitSignature(dir, "f".repeat(40));
  assert.equal(sig.status, "none");
  assert.equal(sig.signer, null);
});
