import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { importSarif } from "../src/scan/sarif-import.js";
import { Ledger } from "../src/ledger/db.js";

function tmp() {
  return mkdtempSync(join(tmpdir(), "vs-sarif-test-"));
}

const SAMPLE_SARIF = {
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "FakeSAST",
          rules: [
            {
              id: "fake.xss",
              defaultConfiguration: { level: "error" },
              properties: { tags: ["A03:2021-Injection"] },
            },
          ],
        },
      },
      results: [
        {
          ruleId: "fake.xss",
          message: { text: "Reflected XSS" },
          locations: [
            { physicalLocation: { artifactLocation: { uri: "src/Web.java" }, region: { startLine: 42 } } },
          ],
        },
      ],
    },
  ],
};

function writeSarif(dir: string, content: unknown = SAMPLE_SARIF): string {
  const path = join(dir, "external.sarif");
  writeFileSync(path, JSON.stringify(content));
  return path;
}

test("SARIF 결과를 findings.db + 원장에 편입시키고, 출처를 external:<도구명>으로 남긴다", () => {
  const repoRoot = tmp();
  const sarifPath = writeSarif(repoRoot);
  const commitHash = "a".repeat(40);

  const { findings, info } = importSarif(repoRoot, sarifPath, commitHash, "dev@example.com");

  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "fake.xss");
  assert.equal(findings[0].severity, "high");
  assert.equal(findings[0].file, "src/Web.java");
  assert.equal(findings[0].line, 42);
  assert.equal(findings[0].ismspClause, "2.8.2 보안 요구사항 검토 및 시험(시큐어코딩 점검) [확인 필요]");
  assert.equal(info.toolName, "FakeSAST");

  const raw = readFileSync(sarifPath);
  assert.equal(info.fileHash, createHash("sha256").update(raw).digest("hex"));

  const ledger = new Ledger(join(repoRoot, ".vibe-supervisor", "ledger.db"));
  const entries = ledger.all();
  ledger.close();
  assert.equal(entries.length, 1);
  assert.equal(entries[0].eventType, "detected");
  assert.ok(entries[0].payload?.kind === "detected");
  if (entries[0].payload?.kind === "detected") {
    assert.equal(entries[0].payload.rulesetVersion, "external:FakeSAST");
    assert.equal(entries[0].payload.rulesetHash, info.fileHash);
  }
  // 어떤 파일을 봤는지 통제할 수 없으므로 재검사 근거로 쓰이지 않게 비워 둔다.
  assert.deepEqual(entries[0].fileHashes, []);
});

test("--tool로 도구 이름을 지정하면 SARIF의 tool.driver.name보다 우선한다", () => {
  const repoRoot = tmp();
  const sarifPath = writeSarif(repoRoot);
  const { info } = importSarif(repoRoot, sarifPath, "b".repeat(40), "dev@example.com", "MyOverrideName");
  assert.equal(info.toolName, "MyOverrideName");
});

test("runs가 없는 SARIF는 명확한 에러로 거부한다", () => {
  const repoRoot = tmp();
  const sarifPath = writeSarif(repoRoot, { version: "2.1.0", runs: [] });
  assert.throws(
    () => importSarif(repoRoot, sarifPath, "c".repeat(40), "dev@example.com"),
    /runs가 없습니다/
  );
});

test("JSON이 아닌 파일은 파싱 에러로 거부한다 (커밋을 막는 대신 명확히 실패)", () => {
  const repoRoot = tmp();
  const sarifPath = join(repoRoot, "broken.sarif");
  writeFileSync(sarifPath, "not json");
  assert.throws(() => importSarif(repoRoot, sarifPath, "d".repeat(40), "dev@example.com"), /파싱할 수 없습니다/);
});
