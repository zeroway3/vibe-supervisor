import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ledger } from "../src/ledger/db.js";
import { FindingsStore } from "../src/findings/store.js";
import { crossCheckFindings } from "../src/ledger/crosscheck.js";
import { rescanEvidence } from "../src/ledger/rescan.js";
import { mapToIsmspClause } from "../src/scan/isms-mapping.js";
import type { Finding } from "../src/report/types.js";

const FILE = "src/UserRepository.java";
const RULE = "ko-baseline.sql-string-concat";
const finding: Finding = {
  ruleId: RULE, severity: "high", file: FILE, line: 12, message: "sql", ismspClause: "-", status: "open",
};

function detected(ledger: Ledger, commit: string, scanned: string[], found: Array<{ findingId: number; ruleId: string; file: string; line: number }>) {
  ledger.append({
    eventType: "detected",
    commitHash: commit.repeat(40).slice(0, 40),
    actor: "dev@example.com",
    aiTool: null,
    originConfidence: "confirmed",
    fileHashes: scanned.map((path) => ({ path, hash: "" })),
    payload: { kind: "detected", rulesetVersion: "v1", rulesetHash: "h", findings: found },
  });
}

function setup() {
  const dir = mkdtempSync(join(tmpdir(), "vs-rescan-"));
  const ledger = new Ledger(join(dir, "ledger.db"));
  const store = new FindingsStore(join(dir, "findings.db"));
  const [id] = store.saveAll("a".repeat(40), [finding]);
  detected(ledger, "a", [FILE], [{ findingId: id, ruleId: RULE, file: FILE, line: 12 }]);
  return { ledger, store, id };
}

test("같은 파일을 다시 검사했는데 같은 규칙이 안 나오면 재검사 근거가 된다", () => {
  const { ledger, store, id } = setup();
  detected(ledger, "b", ["src/Other.java"], []); // 다른 파일만 검사 — 근거 아님
  assert.equal(rescanEvidence(ledger.all(), store.all()).size, 0);

  detected(ledger, "c", [FILE], []);
  const ev = rescanEvidence(ledger.all(), store.all()).get(id);
  assert.equal(ev?.commitHash.slice(0, 1), "c");
  ledger.close();
  store.close();
});

test("사라졌다가 다시 나오면 근거가 없어진다", () => {
  const { ledger, store, id } = setup();
  detected(ledger, "c", [FILE], []);
  const [again] = store.saveAll("d".repeat(40), [{ ...finding, line: 40 }]);
  detected(ledger, "d", [FILE], [{ findingId: again, ruleId: RULE, file: FILE, line: 40 }]);
  assert.equal(rescanEvidence(ledger.all(), store.all()).has(id), false);
  ledger.close();
  store.close();
});

test("전체 검사처럼 대상 파일 목록이 없는 검사는 근거로 쓰지 않는다", () => {
  const { ledger, store } = setup();
  detected(ledger, "c", [], []);
  assert.equal(rescanEvidence(ledger.all(), store.all()).size, 0);
  ledger.close();
  store.close();
});

test("조치 완료(fixed)도 원장 대조 대상이고, 승인으로 바꿔치기하면 걸린다", () => {
  const { ledger, store, id } = setup();
  ledger.append({
    eventType: "fixed",
    commitHash: "c".repeat(40),
    actor: "sec@example.com",
    aiTool: null,
    originConfidence: "confirmed",
    fileHashes: [],
    payload: { kind: "approved", findingId: id, decision: "fixed", note: "PreparedStatement로 수정", ruleId: RULE, file: FILE, line: 12 },
  });
  store.approve(id, "fixed", "sec@example.com", "PreparedStatement로 수정");
  assert.equal(ledger.verify().ok, true);
  assert.deepEqual(crossCheckFindings(ledger.all(), store.all()).issues, []);

  store.approve(id, "approved", "sec@example.com", "PreparedStatement로 수정");
  assert.equal(crossCheckFindings(ledger.all(), store.all()).issues.length, 1);
  ledger.close();
  store.close();
});

test("조항 매핑: 하드코딩 자격증명은 암호키 관리, 인젝션은 점검 조항(2.8.2)", () => {
  assert.match(mapToIsmspClause(["CWE-798: Use of Hard-coded Credentials", "OWASP-A02:2021 - Cryptographic Failures"]), /^2\.7\.2/);
  assert.match(mapToIsmspClause(["OWASP-A02:2021 - Cryptographic Failures"]), /^2\.7\.1/);
  assert.match(mapToIsmspClause(["OWASP-A03:2021 - Injection"]), /^2\.8\.2/);
});
