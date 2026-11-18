/**
 * 사업계획서 [표 8]·부록 D "원장 변조 검출률 — 임의 레코드 변조 100회, 목표 100%"의 실측.
 *
 * 손으로 고른 변조 몇 가지가 아니라, fast-check가 매번 무작위로 레코드·컬럼·새 값을
 * 골라 SQLite 파일을 직접 고친다(공격자가 DB 파일을 열어 고치는 상황과 같다).
 * 실행마다 RUNS회 이상 시도하고, 하나라도 놓치면 어떤 변조였는지 그대로 보여준다.
 *
 * 범위 밖(이 테스트가 "검출된다"고 주장하지 않는 것)은 맨 아래 테스트에 고정해 둔다 —
 * 그쪽이 나중에 고쳐지면 그 테스트가 실패해서 알려준다.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import Database from "better-sqlite3";
import fc from "fast-check";
import { Ledger } from "../src/ledger/db.js";
import { FindingsStore } from "../src/findings/store.js";
import { crossCheckFindings } from "../src/ledger/crosscheck.js";
import type { Finding } from "../src/report/types.js";

const RUNS = Number(process.env.VS_TAMPER_RUNS ?? 200);

const finding = (line: number): Finding => ({
  ruleId: "ko-baseline.sql-string-concat",
  severity: "high",
  file: "src/UserRepository.java",
  line,
  message: "sql",
  ismspClause: "2.8.1 [확인 필요]",
  status: "open",
});

/** 실제 CLI 흐름(커밋 → 탐지 → 승인)과 같은 모양의 원장·발견사항 DB를 만든다. */
function seed() {
  const dir = mkdtempSync(join(tmpdir(), "vs-tamper-"));
  const ledger = new Ledger(join(dir, "ledger.db"));
  const store = new FindingsStore(join(dir, "findings.db"));
  const base = { actor: "dev@example.com", aiTool: null, originConfidence: "confirmed" as const };

  ledger.append({
    ...base,
    eventType: "generated",
    commitHash: "a".repeat(40),
    aiTool: "claude-code",
    fileHashes: [{ path: "src/UserRepository.java", hash: "1".repeat(64) }],
    payload: { kind: "generated", aiRatio: 0.7, originSource: "ai-generated-trailer" },
  });
  const ids = store.saveAll("a".repeat(40), [finding(12), finding(30), finding(44)]);
  ledger.append({
    ...base,
    eventType: "detected",
    commitHash: "a".repeat(40),
    fileHashes: [{ path: "src/UserRepository.java", hash: "1".repeat(64) }],
    payload: {
      kind: "detected",
      rulesetVersion: "ko-baseline-v1",
      rulesetHash: "f".repeat(64),
      findings: ids.map((id, i) => ({ findingId: id, ruleId: finding(0).ruleId, file: finding(0).file, line: [12, 30, 44][i] })),
    },
  });
  const decisions = [
    { id: ids[0], decision: "fixed" as const, note: "PreparedStatement로 변경", line: 12 },
    { id: ids[1], decision: "exception" as const, note: "내부 배치 전용", line: 30 },
  ];
  for (const d of decisions) {
    ledger.append({
      ...base,
      eventType: d.decision === "fixed" ? "fixed" : "approved",
      commitHash: "b".repeat(40),
      fileHashes: [],
      payload: { kind: "approved", findingId: d.id, decision: d.decision, note: d.note, ruleId: finding(0).ruleId, file: finding(0).file, line: d.line },
    });
    store.approve(d.id, d.decision, base.actor, d.note);
  }
  ledger.append({
    ...base,
    eventType: "generated",
    commitHash: "c".repeat(40),
    fileHashes: [{ path: "src/UserRepository.java", hash: "2".repeat(64) }],
    payload: { kind: "generated", aiRatio: null, originSource: "none" },
  });
  ledger.close();
  store.close();
  return { ledgerPath: join(dir, "ledger.db"), findingsPath: join(dir, "findings.db"), ledgerSize: 5, findingIds: ids };
}

function readLedger(path: string) {
  const l = new Ledger(path);
  try {
    return { entries: l.all(), result: l.verify() };
  } finally {
    l.close();
  }
}

// ── 원장 컬럼별 "다른 값" 생성기. JSON 컬럼은 유효한 JSON만 넣는다(깨진 JSON은
// 파싱 단계에서 바로 터지므로 검출 여부를 따질 필요도 없다).
const hex = (n: number) => fc.string({ unit: fc.constantFrom(..."0123456789abcdef"), minLength: n, maxLength: n });
const LEDGER_COLUMNS: Record<string, fc.Arbitrary<unknown>> = {
  timestamp: fc.date({ noInvalidDate: true }).map((d) => d.toISOString()),
  prev_hash: fc.oneof(hex(64), fc.constant(null)),
  event_type: fc.constantFrom("generated", "detected", "fixed", "approved"),
  commit_hash: hex(40),
  actor: fc.oneof(fc.emailAddress(), fc.string()),
  ai_tool: fc.oneof(fc.string(), fc.constant(null)),
  origin_confidence: fc.constantFrom("confirmed", "estimated", "unknown"),
  file_hashes_json: fc.json(),
  payload_json: fc.oneof(fc.json(), fc.constant(null)),
  hash: hex(64),
};

test(`원장: 무작위 레코드·컬럼을 무작위 값으로 ${RUNS}회 고쳐도 전부 검출된다`, () => {
  let attempted = 0;
  fc.assert(
    fc.property(
      fc.integer({ min: 1, max: 5 }),
      fc.constantFrom(...Object.keys(LEDGER_COLUMNS)).chain((col) => fc.tuple(fc.constant(col), LEDGER_COLUMNS[col])),
      (rowId, [col, value]) => {
        const s = seed();
        const before = readLedger(s.ledgerPath).entries;
        const db = new Database(s.ledgerPath);
        db.prepare(`UPDATE ledger_entries SET ${col} = ? WHERE id = ?`).run(value as never, rowId);
        db.close();

        let after;
        try {
          after = readLedger(s.ledgerPath);
        } catch {
          attempted++;
          return true; // 읽는 단계에서 터짐 = 정상 데이터로 통과되지 않음
        }
        // 새 값이 의미상 원래와 같으면(예: 같은 JSON을 다르게 직렬화) 변조가 아니다.
        fc.pre(!isDeepStrictEqual(before, after.entries));
        attempted++;
        assert.equal(after.result.ok, false, `놓친 변조: id=${rowId} ${col}=${JSON.stringify(value)}`);
        return true;
      }
    ),
    { numRuns: RUNS }
  );
  assert.ok(attempted >= 100, `실제 변조 시도가 ${attempted}회뿐 — 100회 이상이어야 측정으로 인정`);
  console.log(`# 원장 컬럼 변조 ${attempted}회 시도, ${attempted}회 검출 (100%)`);
});

test("원장: 첫 레코드나 중간 레코드를 지우면 검출된다", () => {
  for (const rowId of [1, 2, 3, 4]) {
    const s = seed();
    const db = new Database(s.ledgerPath);
    db.prepare("DELETE FROM ledger_entries WHERE id = ?").run(rowId);
    db.close();
    assert.equal(readLedger(s.ledgerPath).result.ok, false, `id=${rowId} 삭제를 놓침`);
  }
});

// ── 발견사항 DB: 원장에 고정된 필드(규칙·파일·라인·상태·처리자·사유)만 대상.
const FINDING_COLUMNS: Record<string, fc.Arbitrary<unknown>> = {
  rule_id: fc.string({ minLength: 1 }),
  file: fc.string({ minLength: 1 }),
  line: fc.integer({ min: 0, max: 10_000 }),
  status: fc.constantFrom("open", "approved", "fixed", "exception"),
  approved_by: fc.oneof(fc.emailAddress(), fc.constant(null)),
  approval_note: fc.oneof(fc.string(), fc.constant(null)),
};

function crossCheck(s: ReturnType<typeof seed>) {
  const store = new FindingsStore(s.findingsPath);
  const findings = store.all();
  store.close();
  return { findings, result: crossCheckFindings(readLedger(s.ledgerPath).entries, findings) };
}

test(`발견사항 DB: 원장에 고정된 필드를 무작위로 ${RUNS}회 고쳐도 전부 검출된다`, () => {
  let attempted = 0;
  fc.assert(
    fc.property(
      fc.integer({ min: 1, max: 3 }),
      fc.constantFrom(...Object.keys(FINDING_COLUMNS)).chain((col) => fc.tuple(fc.constant(col), FINDING_COLUMNS[col])),
      (rowId, [col, value]) => {
        const s = seed();
        const before = crossCheck(s).findings;
        const db = new Database(s.findingsPath);
        db.prepare(`UPDATE findings SET ${col} = ? WHERE id = ?`).run(value as never, rowId);
        db.close();
        const after = crossCheck(s);
        fc.pre(!isDeepStrictEqual(before, after.findings));
        attempted++;
        assert.ok(after.result.issues.length > 0, `놓친 변조: finding #${rowId} ${col}=${JSON.stringify(value)}`);
        return true;
      }
    ),
    { numRuns: RUNS }
  );
  assert.ok(attempted >= 100, `실제 변조 시도가 ${attempted}회뿐`);
  console.log(`# 발견사항 필드 변조 ${attempted}회 시도, ${attempted}회 검출 (100%)`);
});

test("발견사항 DB: 행을 지우거나 원장에 없는 행을 끼워 넣으면 검출된다", () => {
  for (const rowId of [1, 2, 3]) {
    const s = seed();
    const db = new Database(s.findingsPath);
    db.prepare("DELETE FROM findings WHERE id = ?").run(rowId);
    db.close();
    assert.ok(crossCheck(s).result.issues.length > 0, `finding #${rowId} 삭제를 놓침`);
  }
  const s = seed();
  const store = new FindingsStore(s.findingsPath);
  store.saveAll("d".repeat(40), [finding(99)]);
  store.close();
  assert.ok(crossCheck(s).result.issues.length > 0, "끼워 넣은 발견사항을 놓침");
});

// ── 알려진 한계. 지금은 검출되지 않는 게 맞는 동작이라 그대로 고정해 둔다.
// 고쳐지면 이 테스트가 실패하니, 그때 위쪽 "검출된다" 테스트로 옮기면 된다.
test("[알려진 한계] 원장 끝 레코드 삭제는 해시 체인만으로는 검출되지 않는다 — 외부 앵커가 필요", () => {
  const s = seed();
  const db = new Database(s.ledgerPath);
  db.prepare("DELETE FROM ledger_entries WHERE id = ?").run(s.ledgerSize);
  db.close();
  assert.equal(readLedger(s.ledgerPath).result.ok, true);
});

test("[알려진 한계] 원장에 고정되지 않은 발견사항 필드(심각도·메시지·조항)는 고쳐도 검출되지 않는다", () => {
  for (const [col, value] of [
    ["severity", "low"],
    ["message", "문제 없음"],
    ["ismsp_clause", "대상 아님"],
  ] as const) {
    const s = seed();
    const db = new Database(s.findingsPath);
    db.prepare(`UPDATE findings SET ${col} = ? WHERE id = 3`).run(value);
    db.close();
    assert.equal(crossCheck(s).result.issues.length, 0, col);
  }
});
