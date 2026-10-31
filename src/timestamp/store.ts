import Database from "better-sqlite3";
import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS timestamp_anchors (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  anchored_at     TEXT NOT NULL,
  ledger_entry_id INTEGER NOT NULL,
  anchored_hash   TEXT NOT NULL,
  tsa_url         TEXT NOT NULL,
  gen_time        TEXT NOT NULL,
  serial_number   TEXT NOT NULL,
  token_der       BLOB NOT NULL
);
`;

export interface AnchorRecord {
  id: number;
  anchoredAt: string;
  ledgerEntryId: number;
  anchoredHash: string;
  tsaUrl: string;
  genTime: string;
  serialNumber: string;
  tokenDer: Buffer;
}

export class AnchorStore {
  private db: Database.Database;

  constructor(dbPath: string) {
    const dir = dirname(dbPath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA);
  }

  save(record: Omit<AnchorRecord, "id" | "anchoredAt">): AnchorRecord {
    const anchoredAt = new Date().toISOString();
    const result = this.db
      .prepare(
        `INSERT INTO timestamp_anchors
         (anchored_at, ledger_entry_id, anchored_hash, tsa_url, gen_time, serial_number, token_der)
         VALUES (@anchoredAt, @ledgerEntryId, @anchoredHash, @tsaUrl, @genTime, @serialNumber, @tokenDer)`
      )
      .run({ anchoredAt, ...record });
    return { id: result.lastInsertRowid as number, anchoredAt, ...record };
  }

  all(): AnchorRecord[] {
    const rows = this.db.prepare("SELECT * FROM timestamp_anchors ORDER BY id ASC").all() as any[];
    return rows.map((r) => ({
      id: r.id,
      anchoredAt: r.anchored_at,
      ledgerEntryId: r.ledger_entry_id,
      anchoredHash: r.anchored_hash,
      tsaUrl: r.tsa_url,
      genTime: r.gen_time,
      serialNumber: r.serial_number,
      tokenDer: r.token_der,
    }));
  }

  close() {
    this.db.close();
  }
}
