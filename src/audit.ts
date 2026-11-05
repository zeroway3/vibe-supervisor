import { existsSync } from "node:fs";
import { join } from "node:path";
import { Ledger } from "./ledger/db.js";
import { FindingsStore, type StoredFinding } from "./findings/store.js";
import { crossCheckFindings, type CrossCheckIssue } from "./ledger/crosscheck.js";
import { AnchorStore } from "./timestamp/store.js";
import { checkAnchors, type AnchorCheck } from "./timestamp/check.js";
import type { LedgerEntry } from "./ledger/types.js";

/** verify와 report가 같은 판정을 쓰도록 한 곳에서 계산한다. */
export interface AuditResult {
  entries: LedgerEntry[];
  integrity: { ok: boolean; brokenAtId: number | null };
  findings: StoredFinding[];
  crossCheck: { issues: CrossCheckIssue[]; verified: number; unverifiable: number };
  anchorChecks: AnchorCheck[];
  /** 체인·발견사항 대조·앵커가 모두 통과했는가 (앵커가 0건이면 앵커는 통과로 본다 —
   * 대신 리포트에 "없음"이 따로 드러난다) */
  ok: boolean;
}

export async function runAudit(repoRoot: string, trustedPem?: string): Promise<AuditResult> {
  const dir = join(repoRoot, ".vibe-supervisor");

  const ledger = new Ledger(join(dir, "ledger.db"));
  const entries = ledger.all();
  const integrity = ledger.verify();
  ledger.close();

  let findings: StoredFinding[] = [];
  if (existsSync(join(dir, "findings.db"))) {
    const store = new FindingsStore(join(dir, "findings.db"));
    findings = store.all();
    store.close();
  }
  const crossCheck = crossCheckFindings(entries, findings);

  let anchorChecks: AnchorCheck[] = [];
  if (existsSync(join(dir, "anchors.db"))) {
    const anchorStore = new AnchorStore(join(dir, "anchors.db"));
    anchorChecks = await checkAnchors(entries, anchorStore.all(), trustedPem);
    anchorStore.close();
  }

  const ok = integrity.ok && crossCheck.issues.length === 0 && anchorChecks.every((a) => a.token.ok);
  return { entries, integrity, findings, crossCheck, anchorChecks, ok };
}
