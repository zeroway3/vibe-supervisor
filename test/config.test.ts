import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig, saveConfig } from "../src/config/store.js";
import { DEFAULT_CONFIG } from "../src/config/types.js";

function tmp() {
  return mkdtempSync(join(tmpdir(), "vs-config-test-"));
}

test("설정 파일이 없으면 기본값(자동 앵커링 off)을 돌려준다", () => {
  const configPath = join(tmp(), "config.json");
  const config = loadConfig(configPath);
  assert.deepEqual(config, DEFAULT_CONFIG);
});

test("저장하고 다시 읽으면 그대로 돌아온다", () => {
  const configPath = join(tmp(), "config.json");
  saveConfig(configPath, {
    autoAnchor: { enabled: true, everyNCommits: 5, maxAgeHours: 12, tsaUrl: "https://example.com/tsr", timeoutMs: 3000 },
  });
  const loaded = loadConfig(configPath);
  assert.equal(loaded.autoAnchor.enabled, true);
  assert.equal(loaded.autoAnchor.everyNCommits, 5);
  assert.equal(loaded.autoAnchor.tsaUrl, "https://example.com/tsr");
});

test("부분적으로만 적힌 설정은 나머지를 기본값으로 채운다", () => {
  const dir = tmp();
  const configPath = join(dir, "config.json");
  writeFileSync(configPath, JSON.stringify({ autoAnchor: { enabled: true } }));
  const loaded = loadConfig(configPath);
  assert.equal(loaded.autoAnchor.enabled, true);
  assert.equal(loaded.autoAnchor.everyNCommits, DEFAULT_CONFIG.autoAnchor.everyNCommits);
  assert.equal(loaded.autoAnchor.maxAgeHours, DEFAULT_CONFIG.autoAnchor.maxAgeHours);
});

test("설정 파일이 깨져 있으면(JSON 아님) 커밋을 막지 않게 기본값으로 폴백한다", () => {
  const dir = tmp();
  const configPath = join(dir, "config.json");
  writeFileSync(configPath, "{ not valid json");
  const loaded = loadConfig(configPath);
  assert.deepEqual(loaded, DEFAULT_CONFIG);
});
