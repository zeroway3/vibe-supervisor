import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { LedgerEntry, LedgerEntryInput } from "./types.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS ledger_entries (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp        TEXT NOT NULL,
  prev_hash        TEXT,
  event_type       TEXT NOT NULL,
  commit_hash      TEXT NOT NULL,
  actor            TEXT NOT NULL,
  ai_tool          TEXT,
  origin_confidence TEXT NOT NULL,
  file_hashes_json TEXT NOT NULL,
  hash             TEXT NOT NULL
);
`;

export class Ledger {
  private db: Database.Database;

  constructor(dbPath: string) {
    const dir = dirname(dbPath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA);
  }

  /** 체인의 마지막 해시. 레코드가 없으면 null (제네시스 상태). */
  private lastHash(): string | null {
    const row = this.db
      .prepare("SELECT hash FROM ledger_entries ORDER BY id DESC LIMIT 1")
      .get() as { hash: string } | undefined;
    return row?.hash ?? null;
  }

  /** prevHash를 포함한 정규화 필드로 해시를 계산한다. 필드 순서가 바뀌면
   * 기존에 쓰인 모든 해시가 깨지므로 이 함수 내부 순서는 바꾸지 않는다. */
  private computeHash(
    prevHash: string | null,
    timestamp: string,
    input: LedgerEntryInput
  ): string {
    const canonical = JSON.stringify({
      prevHash,
      timestamp,
      eventType: input.eventType,
      commitHash: input.commitHash,
      actor: input.actor,
      aiTool: input.aiTool,
      originConfidence: input.originConfidence,
      fileHashes: input.fileHashes,
    });
    return createHash("sha256").update(canonical).digest("hex");
  }

  append(input: LedgerEntryInput): LedgerEntry {
    const prevHash = this.lastHash();
    const timestamp = new Date().toISOString();
    const hash = this.computeHash(prevHash, timestamp, input);

    const result = this.db
      .prepare(
        `INSERT INTO ledger_entries
         (timestamp, prev_hash, event_type, commit_hash, actor, ai_tool, origin_confidence, file_hashes_json, hash)
         VALUES (@timestamp, @prevHash, @eventType, @commitHash, @actor, @aiTool, @originConfidence, @fileHashesJson, @hash)`
      )
      .run({
        timestamp,
        prevHash,
        eventType: input.eventType,
        commitHash: input.commitHash,
        actor: input.actor,
        aiTool: input.aiTool,
        originConfidence: input.originConfidence,
        fileHashesJson: JSON.stringify(input.fileHashes),
        hash,
      });

    return {
      id: result.lastInsertRowid as number,
      timestamp,
      prevHash,
      hash,
      ...input,
    };
  }

  all(): LedgerEntry[] {
    const rows = this.db
      .prepare("SELECT * FROM ledger_entries ORDER BY id ASC")
      .all() as any[];
    return rows.map((r) => ({
      id: r.id,
      timestamp: r.timestamp,
      prevHash: r.prev_hash,
      eventType: r.event_type,
      commitHash: r.commit_hash,
      actor: r.actor,
      aiTool: r.ai_tool,
      originConfidence: r.origin_confidence,
      fileHashes: JSON.parse(r.file_hashes_json),
      hash: r.hash,
    }));
  }

  /** 체인 전체를 처음부터 다시 계산해 저장된 해시와 비교한다.
   * 중간 레코드가 수정되면 그 이후 전체가 어긋나며 실패 지점이 보고된다. */
  verify(): { ok: boolean; brokenAtId: number | null } {
    const entries = this.all();
    let expectedPrevHash: string | null = null;

    for (const entry of entries) {
      if (entry.prevHash !== expectedPrevHash) {
        return { ok: false, brokenAtId: entry.id };
      }
      const recomputed = this.computeHash(entry.prevHash, entry.timestamp, {
        eventType: entry.eventType,
        commitHash: entry.commitHash,
        actor: entry.actor,
        aiTool: entry.aiTool,
        originConfidence: entry.originConfidence,
        fileHashes: entry.fileHashes,
      });
      if (recomputed !== entry.hash) {
        return { ok: false, brokenAtId: entry.id };
      }
      expectedPrevHash = entry.hash;
    }
    return { ok: true, brokenAtId: null };
  }

  close() {
    this.db.close();
  }
}
