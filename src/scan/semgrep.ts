import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mapToIsmspClause } from "./isms-mapping.js";
import type { Finding, FindingSeverity, RulesetInfo } from "../report/types.js";

interface SarifRule {
  id: string;
  defaultConfiguration?: { level?: string };
  properties?: { tags?: string[] };
}

interface SarifResult {
  ruleId: string;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine: number };
    };
  }>;
}

// semgrep --config <룰셋파일>로 돌리면 ruleId 앞에 호출 시점의 파일 경로가
// 그대로 붙는다(절대경로면 절대경로째로). 로컬 디렉터리 구조를 증빙 리포트에
// 노출하면 안 되므로, 우리 룰 ID 접두사("ko-baseline.")가 나오는 지점부터만
// 남긴다.
function normalizeRuleId(rawId: string): string {
  const marker = "ko-baseline.";
  const idx = rawId.lastIndexOf(marker);
  return idx === -1 ? rawId : rawId.slice(idx);
}

// SARIF는 error/warning/note 3단계뿐이라 report/types.ts의 4단계
// (critical/high/medium/low)로 억지로 끼워 맞추지 않는다 — "критical"은
// 과장이 되므로 의도적으로 안 씀. error→high, warning→medium, note→low.
function mapSeverity(level: string | undefined): FindingSeverity {
  if (level === "error") return "high";
  if (level === "note") return "low";
  return "medium";
}

export function runSemgrepScan(
  repoRoot: string,
  rulesetPath: string,
  targetFiles?: string[]
): { findings: Finding[]; ruleset: RulesetInfo } {
  const rulesetContent = readFileSync(rulesetPath);
  const rulesetHash = createHash("sha256").update(rulesetContent).digest("hex");
  const rulesetVersion = "ko-baseline-v1"; // 파일명과 함께 리포트에 같이 찍힘

  const tmpDir = mkdtempSync(join(tmpdir(), "vs-scan-"));
  const sarifPath = join(tmpDir, "out.sarif");

  try {
    const args = ["--config", rulesetPath, "--sarif", "--output", sarifPath, "--quiet"];
    // targetFiles가 있으면 그 파일들만(증분 스캔) — 없으면 저장소 전체.
    args.push(...(targetFiles && targetFiles.length > 0 ? targetFiles : ["."]));

    try {
      execFileSync("semgrep", args, { cwd: repoRoot, stdio: ["ignore", "ignore", "pipe"] });
    } catch (err: any) {
      // semgrep은 finding이 있으면(blocking rule) 0이 아닌 exit code를 낼 수 있다 —
      // 이건 에러가 아니라 정상적인 "찾았다"는 신호다. sarif 파일이 실제로
      // 생겼는지로 진짜 실패인지 구분한다.
      if (!existsOrThrow(sarifPath)) throw err;
    }

    const sarif = JSON.parse(readFileSync(sarifPath, "utf-8"));
    const run = sarif.runs?.[0];
    if (!run) return { findings: [], ruleset: { version: rulesetVersion, hash: rulesetHash } };

    const rules: SarifRule[] = run.tool?.driver?.rules ?? [];
    const rulesById = new Map(rules.map((r) => [r.id, r]));
    const results: SarifResult[] = run.results ?? [];

    const findings: Finding[] = results.map((r) => {
      const rule = rulesById.get(r.ruleId);
      const tags = rule?.properties?.tags ?? [];
      const loc = r.locations[0]?.physicalLocation;
      return {
        ruleId: normalizeRuleId(r.ruleId),
        severity: mapSeverity(rule?.defaultConfiguration?.level),
        file: loc?.artifactLocation.uri ?? "unknown",
        line: loc?.region.startLine ?? 0,
        message: r.message.text,
        ismspClause: mapToIsmspClause(tags),
        status: "open",
      };
    });

    return { findings, ruleset: { version: rulesetVersion, hash: rulesetHash } };
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
}

function existsOrThrow(path: string): boolean {
  try {
    readFileSync(path);
    return true;
  } catch {
    return false;
  }
}
