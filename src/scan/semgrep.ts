import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
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

/** 로컬 semgrep이 없을 때 쓰는 이미지. 엔진 버전도 결과에 영향을 주므로
 * latest가 아니라 버전을 고정한다(재현성). */
export const SEMGREP_DOCKER_IMAGE = "semgrep/semgrep:1.95.0";

function commandWorks(cmd: string, args: string[]): boolean {
  try {
    execFileSync(cmd, args, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/** 로컬 semgrep을 우선 쓰고, 없으면 Docker 이미지로 대신한다(Windows는 semgrep
 * 네이티브 지원이 약해서 Docker 경로가 현실적인 대안이다). VS_SEMGREP=docker로
 * Docker를 강제할 수 있다. */
export function resolveSemgrepRunner(): { kind: "local" | "docker" } | null {
  if (process.env.VS_SEMGREP !== "docker" && commandWorks("semgrep", ["--version"])) return { kind: "local" };
  if (commandWorks("docker", ["image", "inspect", SEMGREP_DOCKER_IMAGE])) return { kind: "docker" };
  return null;
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

  const runner = resolveSemgrepRunner();
  if (!runner) throw new Error("semgrep을 찾을 수 없습니다 — 'pip install semgrep' 또는 Docker를 설치하세요.");

  try {
    // targetFiles가 있으면 그 파일들만(증분 스캔) — 없으면 저장소 전체.
    const targets = targetFiles && targetFiles.length > 0 ? targetFiles : ["."];
    const { cmd, args } =
      runner.kind === "local"
        ? { cmd: "semgrep", args: ["--config", rulesetPath, "--sarif", "--output", sarifPath, "--quiet", ...targets] }
        : {
            // 저장소·룰셋·출력 폴더를 각각 마운트한다. 경로가 컨테이너 기준으로
            // 바뀌므로 SARIF의 파일 경로는 /src 기준 상대경로로 나온다.
            cmd: "docker",
            args: [
              "run", "--rm",
              "-v", `${repoRoot}:/src`,
              "-v", `${dirname(rulesetPath)}:/rules:ro`,
              "-v", `${tmpDir}:/out`,
              "-w", "/src",
              SEMGREP_DOCKER_IMAGE,
              "semgrep", "--config", `/rules/${basename(rulesetPath)}`,
              "--sarif", "--output", "/out/out.sarif", "--quiet", "--metrics=off",
              ...targets.map((t) => t.replace(/\\/g, "/")),
            ],
          };

    try {
      execFileSync(cmd, args, { cwd: repoRoot, stdio: ["ignore", "ignore", "pipe"] });
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
