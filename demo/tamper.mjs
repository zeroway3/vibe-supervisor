// 데모용 공격 재현 스크립트. 심사원·보안담당자 앞에서 "이 기록을 고치면
// 어떻게 되는가"를 직접 보여주기 위한 것이다. 실제 고객 저장소에는 쓰지 말 것.
//
//   node demo/tamper.mjs <repo> findings-note   발견사항 DB의 승인 사유를 몰래 고친다
//   node demo/tamper.mjs <repo> fake-approval   승인 기록 없이 미승인 항목을 승인 상태로 바꾼다
//   node demo/tamper.mjs <repo> rewrite-chain   원장 첫 기록을 고친 뒤 체인 해시를 전부 다시 계산하고,
//                                               anchors.db의 해시까지 맞춰 고친다(흔적 지우기 시도)
import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { join } from "node:path";

const [repo, mode] = process.argv.slice(2);
if (!repo || !mode) {
  console.error("usage: node demo/tamper.mjs <repo> <findings-note|fake-approval|rewrite-chain>");
  process.exit(1);
}
const dir = join(repo, ".vibe-supervisor");

if (mode === "findings-note") {
  const db = new Database(join(dir, "findings.db"));
  const row = db.prepare("SELECT id FROM findings WHERE status != 'open' ORDER BY id LIMIT 1").get();
  db.prepare("UPDATE findings SET approval_note = ? WHERE id = ?").run("보안팀 검토 완료 (사후에 고친 사유)", row.id);
  db.close();
  console.log(`[공격] 발견사항 #${row.id}의 승인 사유를 DB에서 직접 수정했습니다.`);
} else if (mode === "fake-approval") {
  const db = new Database(join(dir, "findings.db"));
  const row = db.prepare("SELECT id FROM findings WHERE status = 'open' ORDER BY id LIMIT 1").get();
  db.prepare("UPDATE findings SET status = 'approved', approved_by = 'security@example.com', approval_note = '검토 완료' WHERE id = ?").run(row.id);
  db.close();
  console.log(`[공격] 미승인 발견사항 #${row.id}을(를) 원장 기록 없이 '승인' 상태로 바꿨습니다.`);
} else if (mode === "rewrite-chain") {
  const db = new Database(join(dir, "ledger.db"));
  const rows = db.prepare("SELECT * FROM ledger_entries ORDER BY id").all();
  // 첫 커밋을 "사람이 직접 작성"으로 바꾼다 — AI 생성 이력을 지우려는 시나리오.
  rows[0].ai_tool = null;
  rows[0].origin_confidence = "unknown";
  let prev = null;
  const update = db.prepare("UPDATE ledger_entries SET prev_hash = ?, hash = ?, ai_tool = ?, origin_confidence = ? WHERE id = ?");
  const rehashed = new Map();
  for (const r of rows) {
    // 공격자는 해시 계산 방식을 안다고 가정한다(오픈소스이므로).
    const canonical = JSON.stringify({
      prevHash: prev,
      timestamp: r.timestamp,
      eventType: r.event_type,
      commitHash: r.commit_hash,
      actor: r.actor,
      aiTool: r.ai_tool,
      originConfidence: r.origin_confidence,
      fileHashes: JSON.parse(r.file_hashes_json),
      ...(r.payload_json ? { payload: JSON.parse(r.payload_json) } : {}),
    });
    const hash = createHash("sha256").update(canonical).digest("hex");
    update.run(prev, hash, r.ai_tool, r.origin_confidence, r.id);
    rehashed.set(r.id, hash);
    prev = hash;
  }
  db.close();

  // anchors.db의 해시도 새 체인에 맞춰 고친다. TSA 서명 토큰은 다시 만들 수 없다.
  try {
    const adb = new Database(join(dir, "anchors.db"));
    for (const a of adb.prepare("SELECT id, ledger_entry_id FROM timestamp_anchors").all()) {
      adb.prepare("UPDATE timestamp_anchors SET anchored_hash = ? WHERE id = ?").run(rehashed.get(a.ledger_entry_id), a.id);
    }
    adb.close();
  } catch {
    // 앵커가 없는 경우
  }
  console.log(`[공격] 원장 #1을 '사람 작성'으로 고치고 체인 ${rows.length}건의 해시를 전부 다시 계산했습니다. anchors.db도 맞춰 고쳤습니다.`);
} else {
  console.error(`알 수 없는 모드: ${mode}`);
  process.exit(1);
}
