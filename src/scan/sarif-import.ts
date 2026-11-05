import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { Ledger } from "../ledger/db.js";
import { FindingsStore, type StoredFinding } from "../findings/store.js";
import { mapToIsmspClause } from "./isms-mapping.js";
import type { Finding, FindingSeverity } from "../report/types.js";

function mapSeverity(level: string | undefined): FindingSeverity {
  if (level === "error") return "high";
  if (level === "note") return "low";
  return "medium";
}

export interface SarifImportInfo {
  toolName: string;
  /** 가져온 SARIF 파일 자체의 sha256. 우리가 버전을 고정할 수 있는 자체
   * 룰셋과 달리, 외부 도구 결과는 "이 파일을 그대로 가져왔다"는 것만 증명
   * 가능하다 — rulesetHash 자리에 이 값을 대신 넣는 이유. */
  fileHash: string;
}

/**
 * semgrep이 아닌 외부 SAST/DAST 도구가 낸 SARIF 2.1.0 결과를 scanAndRecord와
 * 같은 저장 형태(findings.db + 원장 detected 레코드)로 편입시킨다. 다른 점은
 * 재현성 근거뿐이다 — semgrep 경로는 "우리 룰셋 파일 해시"를, 이 경로는 "가져온
 * SARIF 파일 해시"를 rulesetHash 자리에 쓴다(도구 이름은 rulesetVersion 자리에
 * "external:<tool>"로). 어떤 파일을 스캔했는지는 우리가 통제할 수 없으므로
 * fileHashes는 비워 둔다 — 그래서 rescanEvidence의 재검사 근거로는 쓰이지
 * 않는다(의도된 동작: 모르는 걸 안다고 하지 않는다).
 */
export function importSarif(
  repoRoot: string,
  sarifPath: string,
  commitHash: string,
  actor: string,
  toolNameOverride?: string
): { findings: StoredFinding[]; info: SarifImportInfo } {
  const raw = readFileSync(sarifPath);
  const fileHash = createHash("sha256").update(raw).digest("hex");

  let sarif: any;
  try {
    sarif = JSON.parse(raw.toString("utf-8"));
  } catch (err: any) {
    throw new Error(`SARIF 파일을 JSON으로 파싱할 수 없습니다: ${err.message}`);
  }
  const run = sarif.runs?.[0];
  if (!run) throw new Error("SARIF 파일에 runs가 없습니다 — SARIF 2.1.0 형식인지 확인하세요.");

  const toolName = toolNameOverride ?? run.tool?.driver?.name ?? "unknown-external-tool";
  const rules: any[] = run.tool?.driver?.rules ?? [];
  const rulesById = new Map(rules.map((r) => [r.id, r]));
  const results: any[] = run.results ?? [];

  const findings: Finding[] = results.map((r) => {
    const rule = rulesById.get(r.ruleId);
    const tags: string[] = rule?.properties?.tags ?? [];
    const loc = r.locations?.[0]?.physicalLocation;
    return {
      ruleId: r.ruleId ?? "unknown-rule",
      severity: mapSeverity(rule?.defaultConfiguration?.level ?? r.level),
      file: loc?.artifactLocation?.uri ?? "unknown",
      line: loc?.region?.startLine ?? 0,
      message: r.message?.text ?? "",
      ismspClause: mapToIsmspClause(tags),
      status: "open",
    };
  });

  const findingsStore = new FindingsStore(join(repoRoot, ".vibe-supervisor", "findings.db"));
  const ids = findingsStore.saveAll(commitHash, findings);
  const stored = findingsStore.all().filter((f) => ids.includes(f.id));
  findingsStore.close();

  const ledger = new Ledger(join(repoRoot, ".vibe-supervisor", "ledger.db"));
  ledger.append({
    eventType: "detected",
    commitHash,
    actor,
    aiTool: null,
    originConfidence: "confirmed",
    fileHashes: [],
    payload: {
      kind: "detected",
      rulesetVersion: `external:${toolName}`,
      rulesetHash: fileHash,
      findings: stored.map((f) => ({ findingId: f.id, ruleId: f.ruleId, file: f.file, line: f.line })),
    },
  });
  ledger.close();

  return { findings: stored, info: { toolName, fileHash } };
}
