import { test } from "node:test";
import assert from "node:assert/strict";
import { parseAiTrailer } from "../src/trailer/parse.js";

test("AI-Generated 트레일러는 확정, ratio도 함께 읽는다", () => {
  const r = parseAiTrailer("feat: 결제\n\nAI-Generated: claude-code, ratio=0.7\n");
  assert.deepEqual(r, { aiTool: "claude-code", aiRatio: 0.7, confidence: "confirmed", originSource: "ai-generated-trailer" });
});

test("범위를 벗어난 ratio는 버린다", () => {
  assert.equal(parseAiTrailer("x\n\nAI-Generated: copilot, ratio=7\n").aiRatio, null);
  assert.equal(parseAiTrailer("x\n\nAI-Generated: copilot\n").aiRatio, null);
});

test("AI 도구의 공동작성자 트레일러는 추정", () => {
  const r = parseAiTrailer("fix\n\nCo-Authored-By: Claude Opus <noreply@anthropic.com>\n");
  assert.equal(r.confidence, "estimated");
  assert.equal(r.aiTool, "claude");
});

test("Grok 공동작성자 트레일러는 추정", () => {
  const byName = parseAiTrailer("feat\n\nCo-Authored-By: Grok Bot <noreply@x.ai>\n");
  assert.equal(byName.confidence, "estimated");
  assert.equal(byName.aiTool, "grok");
  const byDomain = parseAiTrailer("feat\n\nCo-Authored-By: Assistant <bot@x.ai>\n");
  assert.equal(byDomain.confidence, "estimated");
  assert.equal(byDomain.aiTool, "grok");
});

test("사람 공동작성자만 있으면 미상", () => {
  const r = parseAiTrailer("fix\n\nCo-authored-by: 김태희 <th@example.com>\n");
  assert.equal(r.confidence, "unknown");
  assert.equal(r.aiTool, null);
});

test("선언과 공동작성자가 같이 있으면 선언(확정)이 우선", () => {
  const r = parseAiTrailer("fix\n\nAI-Generated: cursor, ratio=0.3\nCo-Authored-By: Claude <noreply@anthropic.com>\n");
  assert.equal(r.confidence, "confirmed");
  assert.equal(r.aiTool, "cursor");
});
