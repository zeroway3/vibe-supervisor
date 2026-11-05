import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { Ledger } from "../src/ledger/db.js";
import { FindingsStore } from "../src/findings/store.js";
import { crossCheckFindings } from "../src/ledger/crosscheck.js";
import type { Finding } from "../src/report/types.js";

function tmp() {
  return mkdtempSync(join(tmpdir(), "vs-test-"));
}

const base = {
  commitHash: "a".repeat(40),
  actor: "dev@example.com",
  aiTool: null,
  originConfidence: "confirmed" as const,
  fileHashes: [],
};

const sampleFinding: Finding = {
  ruleId: "ko-baseline.sql-string-concat",
  severity: "high",
  file: "src/UserRepository.java",
  line: 12,
  message: "sql",
  ismspClause: "2.8.1 [확인 필요]",
  status: "open",
};

/** 실제 CLI와 같은 순서로 탐지 → 원장 기록 → 승인 → 원장 기록을 만든다. */
function seed(dir: string) {
  const ledger = new Ledger(join(dir, "ledger.db"));
  const store = new FindingsStore(join(dir, "findings.db"));
  const ids = store.saveAll(base.commitHash, [sampleFinding, { ...sampleFinding, line: 30 }]);
  ledger.append({
    ...base,
    eventType: "detected",
    payload: {
      kind: "detected",
      rulesetVersion: "v1",
      rulesetHash: "h",
      findings: ids.map((id, i) => ({ findingId: id, ruleId: sampleFinding.ruleId, file: sampleFinding.file, line: i === 0 ? 12 : 30 })),
    },
  });
  ledger.append({
    ...base,
    eventType: "approved",
    payload: { kind: "approved", findingId: ids[0], decision: "approved", note: "수정 완료", ruleId: sampleFinding.ruleId, file: sampleFinding.file, line: 12 },
  });
  store.approve(ids[0], "approved", base.actor, "수정 완료");
  return { ledger, store, ids };
}

test("payload까지 포함해 체인이 검증되고, payload를 고치면 깨진다", () => {
  const dir = tmp();
  const { ledger, store } = seed(dir);
  assert.deepEqual(ledger.verify(), { ok: true, brokenAtId: null });
  ledger.close();
  store.close();

  const raw = new Database(join(dir, "ledger.db"));
  const row = raw.prepare("SELECT payload_json FROM ledger_entries WHERE id = 2").get() as { payload_json: string };
  raw.prepare("UPDATE ledger_entries SET payload_json = ? WHERE id = 2").run(row.payload_json.replace("수정 완료", "다른 사유"));
  raw.close();

  const reopened = new Ledger(join(dir, "ledger.db"));
  assert.deepEqual(reopened.verify(), { ok: false, brokenAtId: 2 });
  reopened.close();
});

test("payload 컬럼이 없던 구버전 원장도 열리고 그대로 검증된다", () => {
  const dir = tmp();
  const raw = new Database(join(dir, "ledger.db"));
  raw.exec(`CREATE TABLE ledger_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, prev_hash TEXT,
    event_type TEXT NOT NULL, commit_hash TEXT NOT NULL, actor TEXT NOT NULL, ai_tool TEXT,
    origin_confidence TEXT NOT NULL, file_hashes_json TEXT NOT NULL, hash TEXT NOT NULL)`);
  raw.close();

  // 구버전 해시 계산 방식(payload 없음)으로 레코드를 쓴 것과 같은 상태를 만든다.
  const ledger = new Ledger(join(dir, "ledger.db"));
  ledger.append({ ...base, eventType: "generated" });
  ledger.append({ ...base, eventType: "generated", payload: { kind: "generated", aiRatio: 0.5, originSource: "ai-generated-trailer" } });
  assert.equal(ledger.verify().ok, true);
  assert.equal(ledger.all()[0].payload, undefined);
  ledger.close();
});

test("발견사항 DB를 직접 고치면 원장 대조에서 걸린다", () => {
  const dir = tmp();
  const { ledger, store, ids } = seed(dir);

  assert.deepEqual(crossCheckFindings(ledger.all(), store.all()).issues, []);

  // 1) 승인 기록 없이 상태만 바꾼 경우
  store.approve(ids[1], "approved", "boss@example.com", "몰래 승인");
  let r = crossCheckFindings(ledger.all(), store.all());
  assert.equal(r.issues.length, 1);
  assert.equal(r.issues[0].findingId, ids[1]);

  // 2) 이미 승인된 항목의 사유를 사후에 고친 경우
  store.approve(ids[0], "approved", base.actor, "사후에 그럴듯하게 고친 사유");
  r = crossCheckFindings(ledger.all(), store.all());
  assert.equal(r.issues.length, 2);

  ledger.close();
  store.close();
});

test("발견사항을 지우거나 끼워 넣으면 걸린다", () => {
  const dir = tmp();
  const { ledger, store, ids } = seed(dir);
  store.close();

  const raw = new Database(join(dir, "findings.db"));
  raw.prepare("DELETE FROM findings WHERE id = ?").run(ids[1]);
  raw.close();

  const store2 = new FindingsStore(join(dir, "findings.db"));
  store2.saveAll(base.commitHash, [{ ...sampleFinding, line: 99 }]);
  const r = crossCheckFindings(ledger.all(), store2.all());
  const messages = r.issues.map((i) => i.message).join("\n");
  assert.match(messages, /사라졌습니다/);
  assert.match(messages, /탐지 기록이 없는/);
  ledger.close();
  store2.close();
});
