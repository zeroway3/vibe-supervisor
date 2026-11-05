import Database from "better-sqlite3";
import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { Finding, FindingDecision } from "../report/types.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS findings (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_timestamp TEXT NOT NULL,
  commit_hash    TEXT NOT NULL,
  rule_id        TEXT NOT NULL,
  severity       TEXT NOT NULL,
  file           TEXT NOT NULL,
  line           INTEGER NOT NULL,
  message        TEXT NOT NULL,
  ismsp_clause   TEXT NOT NULL,
  status         TEXT NOT NULL DEFAULT 'open',
  approved_by    TEXT,
  approval_note  TEXT
);
`;

export interface StoredFinding extends Finding {
  id: number;
  scanTimestamp: string;
  commitHash: string;
}

export class FindingsStore {
  private db: Database.Database;

  constructor(dbPath: string) {
    const dir = dirname(dbPath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA);
  }

  /** 저장된 id를 입력 순서대로 돌려준다 — 원장의 detected 레코드가 이 id를 고정한다. */
  saveAll(commitHash: string, findings: Finding[]): number[] {
    const scanTimestamp = new Date().toISOString();
    const insert = this.db.prepare(
      `INSERT INTO findings
       (scan_timestamp, commit_hash, rule_id, severity, file, line, message, ismsp_clause, status)
       VALUES (@scanTimestamp, @commitHash, @ruleId, @severity, @file, @line, @message, @ismspClause, 'open')`
    );
    const tx = this.db.transaction((rows: Finding[]) =>
      rows.map((f) => Number(insert.run({ scanTimestamp, commitHash, ...f }).lastInsertRowid))
    );
    return tx(findings);
  }

  get(id: number): StoredFinding | undefined {
    return this.all().find((f) => f.id === id);
  }

  all(): StoredFinding[] {
    const rows = this.db.prepare("SELECT * FROM findings ORDER BY id ASC").all() as any[];
    return rows.map((r) => ({
      id: r.id,
      scanTimestamp: r.scan_timestamp,
      commitHash: r.commit_hash,
      ruleId: r.rule_id,
      severity: r.severity,
      file: r.file,
      line: r.line,
      message: r.message,
      ismspClause: r.ismsp_clause,
      status: r.status,
      approvedBy: r.approved_by ?? undefined,
      approvalNote: r.approval_note ?? undefined,
    }));
  }

  approve(id: number, status: FindingDecision, approvedBy: string, note?: string): boolean {
    const result = this.db
      .prepare(
        "UPDATE findings SET status = @status, approved_by = @approvedBy, approval_note = @note WHERE id = @id"
      )
      .run({ id, status, approvedBy, note: note ?? null });
    return result.changes > 0;
  }

  close() {
    this.db.close();
  }
}
