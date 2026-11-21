import type { LedgerEntry } from "../ledger/types.js";
import type { CrossCheckIssue } from "../ledger/crosscheck.js";
import type { AnchorCheck } from "../timestamp/check.js";
import { rescanEvidence, type RescanEvidence } from "../ledger/rescan.js";
import type { CompletenessResult } from "../ledger/completeness.js";
import { DECISION_LABEL, type ReportInput, type Finding } from "./types.js";
import type { ApprovalSignatureSummary } from "../signing/approval.js";

/** 리포트에 필요한 검증 결과. CLI는 audit.ts의 AuditResult를 그대로 넘기고,
 * 샘플(demo.ts)은 가짜 값을 채워 넘긴다. */
export interface ReportAudit {
  entries: LedgerEntry[];
  integrity: { ok: boolean; brokenAtId: number | null };
  crossCheck: { issues: CrossCheckIssue[]; verified: number; unverifiable: number };
  anchorChecks: AnchorCheck[];
  /** git 이력 대비 기록 누락 검사 결과. 샘플 리포트처럼 git 이력이 없으면 생략한다. */
  completeness?: CompletenessResult;
  /** 샘플 리포트(demo.ts)는 생략할 수 있다 — 생략하면 승인 서명 항목을 "기록 없음"으로 표기. */
  approvalSignatures?: ApprovalSignatureSummary;
}

/** 기록 완전성 요약 — 표의 한 줄 라벨과 6장 상세. */
function completenessSummary(c: CompletenessResult | undefined): { label: string; detail: string } {
  if (!c) return { label: "— (확인하지 않음)", detail: "_이 리포트는 git 이력과의 대조 없이 생성되었습니다._" };
  if (c.baseline === null) {
    return {
      label: "⚠ 확인 범위 없음",
      detail: "현재 브랜치 이력에 원장에 기록된 커밋이 없어 기록 누락 여부를 확인할 수 없습니다.",
    };
  }
  const base = `기준 커밋 \`${c.baseline.slice(0, 8)}\`(원장에 기록된 가장 오래된 커밋) 이후 일반 커밋 ${c.checked}건을 git 이력과 대조했습니다.`;
  const label =
    c.missing.length === 0
      ? `✅ 커밋 ${c.checked}건 모두 기록됨${c.scanGaps.length > 0 ? ` (검사 기록 없는 커밋 ${c.scanGaps.length}건)` : ""}`
      : `❌ 기록 누락 커밋 ${c.missing.length}건 / ${c.checked}건`;

  const parts = [base];
  if (c.missing.length > 0) {
    parts.push(
      `\n**❌ 원장에 기록되지 않은 커밋 ${c.missing.length}건** — 훅이 설치되지 않은 곳에서 만들었거나 훅을 우회한 커밋입니다. ` +
        `이 커밋들은 출처 기록과 커밋 시점 보안 검사가 없습니다.\n\n| 커밋 | 작성일 | 작성자 | 제목 |\n|---|---|---|---|\n` +
        c.missing
          .slice(0, 50)
          .map((m) => `| \`${m.hash.slice(0, 8)}\` | ${m.date.slice(0, 10)} | ${cell(m.author)} | ${cell(m.subject)} |`)
          .join("\n") +
        (c.missing.length > 50 ? `\n\n… 외 ${c.missing.length - 50}건` : "")
    );
  }
  if (c.scanGaps.length > 0) {
    parts.push(
      `\n**⚠ 보안 검사 기록이 없는 커밋 ${c.scanGaps.length}건** — 커밋은 기록됐지만 바뀐 파일이 이후 어떤 검사에도 포함되지 않았습니다 ` +
        `(검사를 건너뛰었거나 검사 도구가 없었던 경우).\n\n` +
        c.scanGaps
          .slice(0, 30)
          .map((g) => `- \`${g.commitHash.slice(0, 8)}\`: ${g.files.slice(0, 5).map(cell).join(", ")}${g.files.length > 5 ? ` 외 ${g.files.length - 5}개` : ""}`)
          .join("\n")
    );
  }
  if (c.lateScanned > 0) {
    parts.push(`\n- 커밋 시점이 아니라 이후 검사로만 확인된 커밋: ${c.lateScanned}건`);
  }
  if (c.unrecordedMerges.length > 0) {
    parts.push(
      `\n- 기록이 없는 병합 커밋: ${c.unrecordedMerges.length}건 — git merge는 커밋 훅을 실행하지 않아 누락으로 보지 않았습니다. ` +
        `병합 과정에서 코드가 바뀌지 않았는지는 별도 확인이 필요합니다.`
    );
  }
  if (c.orphaned.length > 0) {
    parts.push(
      `\n- 원장에는 있지만 현재 이력에 없는 커밋: ${c.orphaned.length}건 — amend·rebase·reset으로 이력이 바뀐 경우입니다. ` +
        `기록 이후 이력이 바뀌었다는 사실을 숨기지 않고 표기합니다.`
    );
  }
  return { label, detail: parts.join("\n") };
}

function approvalSignatureSummary(s: ApprovalSignatureSummary | undefined): { label: string; detail: string } {
  if (!s || s.total === 0) {
    return { label: "— 승인 기록 없음", detail: "_승인·예외 처리 기록이 없습니다._" };
  }
  const failRows = s.failed.map(
    (f) => `- ❌ 원장 #${f.entryId} (발견사항 #${f.findingId}, ${cell(f.actor)}): ${f.check!.message}`
  );
  const label =
    s.failed.length > 0
      ? `❌ ${s.failed.length}건 서명 검증 실패`
      : s.good === 0
        ? `⚠ ${s.total}건 모두 서명 없음 (git 이메일 자기신고)`
        : `${s.unsigned === 0 ? "✅" : "⚠"} ${s.good}/${s.total}건 서명 유효` +
          (s.allowedSignersUsed ? ` (본인 키 확인 ${s.trusted}건)` : " (키 소유자 미확인)");
  const rows = s.checks
    .map((c) => {
      const st = !c.check
        ? "서명 없음"
        : { valid: "유효 (키 소유자 미확인)", trusted: "유효 · 본인 키", untrusted: "❌ 등록되지 않은 키", invalid: "❌ 내용 불일치" }[
            c.check.status
          ];
      return `| #${c.entryId} | #${c.findingId} | ${cell(c.actor)} | ${st} | ${c.check ? `\`${c.check.fingerprint}\`` : "-"} |`;
    })
    .join("\n");
  return {
    label,
    detail:
      `| 원장 | 발견사항 | 처리자 | 서명 | 키 지문 |\n|---|---|---|---|---|\n${rows}` +
      (failRows.length > 0 ? `\n\n${failRows.join("\n")}` : "") +
      (s.allowedSignersUsed
        ? ""
        : `\n\n> 서명이 맞는지는 확인했지만, 그 키가 처리자 본인의 것인지는 확인하지 않았습니다. ` +
          `\`report --allowed-signers <파일>\`로 생성하면 등록된 본인 키인지까지 표기됩니다.`),
  };
}

type ReportFinding = Finding & { id?: number; commitHash?: string };

function pct(n: number, total: number): string {
  if (total === 0) return "0%";
  return `${((n / total) * 100).toFixed(1)}%`;
}

/** 출처 분포는 커밋 기록(generated)만 센다 — 스캔·승인 레코드까지 세면
 * "확정" 비율이 부풀려진다. */
function originStats(entries: LedgerEntry[]) {
  const commits = entries.filter((e) => e.eventType === "generated");
  const count = (c: string) => commits.filter((e) => e.originConfidence === c).length;
  const ratios = commits
    .map((e) => (e.payload?.kind === "generated" ? e.payload.aiRatio : null))
    .filter((r): r is number => r !== null);
  const tools = new Map<string, number>();
  for (const e of commits) if (e.aiTool) tools.set(e.aiTool, (tools.get(e.aiTool) ?? 0) + 1);
  // 서명 통계는 payload.signature가 있는 커밋만 센다(이 필드가 생기기 전
  // 원장은 "알 수 없음"이지 "미서명"이 아니다 — 구분해서 표기).
  const withSignatureInfo = commits.filter((e) => e.payload?.kind === "generated" && e.payload.signature);
  const signed = withSignatureInfo.filter(
    (e) => e.payload?.kind === "generated" && e.payload.signature?.status === "good"
  ).length;
  return {
    total: commits.length,
    confirmed: count("confirmed"),
    estimated: count("estimated"),
    unknown: count("unknown"),
    avgRatio: ratios.length > 0 ? ratios.reduce((a, b) => a + b, 0) / ratios.length : null,
    ratioSamples: ratios.length,
    tools,
    signed,
    signatureKnown: withSignatureInfo.length,
    byCommit: new Map(commits.map((e) => [e.commitHash, e])),
  };
}

/** 발견사항별로 원장에 남은 처리 시각. 승인을 "나중에 몰아서 썼는지"가 아니라
 * "그때 했는지"를 보여주는 게 이 리포트의 핵심이라 시각을 같이 찍는다. */
function approvalTimes(entries: LedgerEntry[]): Map<number, string> {
  const m = new Map<number, string>();
  for (const e of entries) if (e.payload?.kind === "approved") m.set(e.payload.findingId, e.timestamp);
  return m;
}

function detectionTimes(entries: LedgerEntry[]): Map<number, string> {
  const m = new Map<number, string>();
  for (const e of entries) {
    if (e.payload?.kind !== "detected") continue;
    for (const f of e.payload.findings) m.set(f.findingId, e.timestamp);
  }
  return m;
}

/** 발견사항이 어느 룰셋/도구에서 나왔는지. semgrep은 고정 룰셋 파일 해시를,
 * import-sarif로 들어온 건 "external:<도구명>" + 가져온 SARIF 파일 해시를
 * 쓴다 — 전부 같은 ruleset으로 나왔다고 전제하면 안 된다(여러 출처가 섞일 수
 * 있음). */
interface DetectionSource {
  version: string;
  hash: string;
}

function detectionSources(entries: LedgerEntry[]): Map<number, DetectionSource> {
  const m = new Map<number, DetectionSource>();
  for (const e of entries) {
    if (e.payload?.kind !== "detected") continue;
    const source = { version: e.payload.rulesetVersion, hash: e.payload.rulesetHash };
    for (const f of e.payload.findings) m.set(f.findingId, source);
  }
  return m;
}

/** 리포트 요약(1·5장)에 쓸, 이 기간에 실제로 쓰인 서로 다른 탐지 출처 목록.
 * 하나뿐이면 지금까지처럼 input.ruleset(semgrep 고정 룰셋)만 보여주면 되지만,
 * SARIF를 가져온 적이 있으면 그 출처도 같이 나열해야 "룰셋 X로만 재현 가능"이라는
 * 말이 거짓이 되지 않는다. */
function distinctSources(entries: LedgerEntry[], fallback: DetectionSource): DetectionSource[] {
  const sources = detectionSources(entries);
  const seen = new Map<string, DetectionSource>();
  for (const s of sources.values()) seen.set(`${s.version}:${s.hash}`, s);
  if (seen.size === 0) return [fallback];
  return [...seen.values()];
}

/** 표 칸에 들어가는 사용자 입력(승인 사유·이메일 등)의 세로선·줄바꿈이 표를
 * 깨지 않게 한다. */
function cell(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function shortTime(iso: string | undefined): string {
  return iso ? iso.replace("T", " ").slice(0, 16) : "-";
}

/** "조치 완료"는 원장의 재검사 기록으로 뒷받침되는지까지 같이 적는다. 근거가 없으면
 * 숨기지 않고 "재검사 근거 없음"이라고 쓴다. 반대로 아직 미승인인데 재검사에서
 * 사라진 항목은 담당자가 조치 여부를 확인하도록 표시만 한다(자동으로 닫지 않음). */
function statusText(status: Finding["status"], ev: RescanEvidence | undefined): string {
  const where = ev ? `커밋 ${ev.commitHash.slice(0, 7)}` : "";
  if (status === "fixed") return ev ? `조치 완료 (재검사 확인: ${where})` : "조치 완료 (재검사 근거 없음)";
  if (status === "open") return ev ? `⚠ 미승인 (${where} 재검사에서 사라짐 — 조치 확인 필요)` : "⚠ 미승인";
  return DECISION_LABEL[status];
}

function findingsTable(findings: ReportFinding[], audit: ReportAudit, origin: ReturnType<typeof originStats>): string {
  if (findings.length === 0) return "_이 기간 동안 탐지된 항목이 없습니다._";
  const detected = detectionTimes(audit.entries);
  const sources = detectionSources(audit.entries);
  const approved = approvalTimes(audit.entries);
  const issueIds = new Set(audit.crossCheck.issues.map((i) => i.findingId));
  const rescan = rescanEvidence(
    audit.entries,
    findings.filter((f): f is ReportFinding & { id: number } => f.id !== undefined)
  );

  const header =
    "| # | 규칙 | 심각도 | 파일:라인 | 출처(커밋) | 탐지 도구 | 관련 기준(취약점 유형) | 탐지 시각 | 상태 | 처리 시각 | 처리자 — 사유 |\n" +
    "|---|---|---|---|---|---|---|---|---|---|---|";
  const rows = findings.map((f, idx) => {
    const id = f.id ?? idx + 1;
    const ev = f.id !== undefined ? rescan.get(f.id) : undefined;
    const statusLabel = statusText(f.status, ev);
    const actor = f.approvedBy ? cell(`${f.approvedBy}${f.approvalNote ? ` — ${f.approvalNote}` : ""}`) : "-";
    const commit = f.commitHash ? origin.byCommit.get(f.commitHash) : undefined;
    const src = commit ? `${commit.originConfidence}${commit.aiTool ? ` (${commit.aiTool})` : ""}` : "-";
    const tool = f.id !== undefined ? sources.get(f.id)?.version ?? "-" : "-";
    const flag = issueIds.has(id) ? " ❌원장 불일치" : "";
    return (
      `| ${id} | ${f.ruleId} | ${f.severity} | ${cell(f.file)}:${f.line} | ${src} | ${cell(tool)} | ${f.ismspClause} | ` +
      `${shortTime(f.id !== undefined ? detected.get(f.id) : undefined)} | ${statusLabel}${flag} | ` +
      `${shortTime(f.id !== undefined ? approved.get(f.id) : undefined)} | ${actor} |`
    );
  });
  return [header, ...rows].join("\n");
}

function anchorSummary(checks: AnchorCheck[]): { label: string; detail: string } {
  if (checks.length === 0) {
    return {
      label: "⚠ 없음 — 소급 재생성 여부를 외부적으로 증명할 수 없음",
      detail: "아직 등록된 앵커가 없습니다.",
    };
  }
  const failed = checks.filter((c) => !c.token.ok);
  const latest = checks[checks.length - 1].token;
  const chain = checks.every((c) => c.token.chainChecked);
  if (failed.length > 0) {
    return {
      label: `❌ ${failed.length}/${checks.length}건 실패 — 소급 재생성 또는 앵커 조작 의심`,
      detail: failed.map((c) => `- 앵커 #${c.anchor.id} (원장 #${c.anchor.ledgerEntryId}): ${c.token.message}`).join("\n"),
    };
  }
  const rows = checks
    .map(
      (c) =>
        `| ${c.anchor.id} | #${c.anchor.ledgerEntryId} | ${c.token.genTime} | ${c.token.signer ?? "-"} | \`${c.token.serialNumberHex}\` |`
    )
    .join("\n");
  return {
    label: `✅ ${checks.length}건 서명·해시 일치 (최근 ${latest.genTime})${chain ? "" : " — 인증서 체인 미확인"}`,
    detail:
      `| 앵커 | 원장 위치 | TSA 서명 시각 | 서명자 | 일련번호 |\n|---|---|---|---|---|\n${rows}\n\n` +
      `위 시각은 TSA가 서명한 토큰 안에서 읽은 값이며, 로컬 DB에 따로 적힌 값이 아닙니다. ` +
      `각 앵커 시점까지의 원장은 그 이후 다시 만들어지지 않았음이 확인됩니다.` +
      (chain
        ? ""
        : `\n\n> 서명자 인증서가 신뢰할 수 있는 루트로 이어지는지(인증서 체인)는 이번 생성 시 확인하지 않았습니다. ` +
          `\`report --tsa-ca <TSA 루트 인증서>\`로 생성하면 체인까지 확인한 결과가 표기됩니다.`),
  };
}

export function generateReport(input: ReportInput, audit: ReportAudit): string {
  const findings = input.findings as ReportFinding[];
  const origin = originStats(audit.entries);
  const sourcesUsed = distinctSources(audit.entries, { version: input.ruleset.version, hash: input.ruleset.hash });
  const unapproved = findings.filter((f) => f.status === "open");
  const exceptions = findings.filter((f) => f.status === "exception");
  const fixedCount = findings.filter((f) => f.status === "fixed").length;
  const acceptedCount = findings.filter((f) => f.status === "approved").length;
  const aiUnapproved = unapproved.filter((f) => {
    const c = f.commitHash ? origin.byCommit.get(f.commitHash) : undefined;
    return c && c.originConfidence !== "unknown";
  });
  const anchors = anchorSummary(audit.anchorChecks);
  const completeness = completenessSummary(audit.completeness);
  const approvalSigs = approvalSignatureSummary(audit.approvalSignatures);
  const cc = audit.crossCheck;
  const scans = audit.entries.filter((e) => e.eventType === "detected").length;
  const approvals = audit.entries.filter((e) => e.payload?.kind === "approved").length;

  const warningBlock = input.isSample
    ? `> ⚠ 이 리포트는 **데모용 샘플 데이터**로 생성되었습니다. 실제 고객 저장소의
> 실데이터가 아니며, ISMS-P 조항 매핑도 재검증이 필요한 추정값입니다.
> 심사 자료로서의 수용 가능성을 확인하기 위한 형식 검토용 샘플입니다.`
    : `> ⚠ 이 리포트는 이 저장소의 **실제 원장·스캔 기록**으로 생성되었습니다.
> 다만 ISMS-P 조항 매핑은 아직 현직 심사원 검증을 거치지 않은 추정값입니다 —
> "[확인 필요]" 표기가 붙은 항목은 심사 근거로 그대로 인용하지 마세요.`;

  const ccLabel =
    cc.issues.length === 0
      ? `✅ ${cc.verified}건 일치${cc.unverifiable > 0 ? ` (구버전 ${cc.unverifiable}건 대조 근거 없음)` : ""}`
      : `❌ ${cc.issues.length}건 불일치`;

  return `# 바이브 슈퍼바이저 — 개발보안 감독 리포트${input.isSample ? " (샘플)" : ""}

${warningBlock}

| 항목 | 값 |
|---|---|
| 대상 저장소 | ${cell(input.repoName)} |
| 집계 기간 | ${input.periodStart} ~ ${input.periodEnd} |
| 룰셋 버전 | ${input.ruleset.version} (hash: \`${input.ruleset.hash.slice(0, 16)}…\`)${sourcesUsed.length > 1 ? ` — 그 외 탐지 출처 ${sourcesUsed.length - 1}건 추가 (5장 참고)` : ""} |
| 생성 시각 | ${new Date().toISOString()} |
| 원장 무결성 (해시 체인) | ${audit.integrity.ok ? "✅ 정상 (변조 흔적 없음)" : `❌ 깨짐 — id=${audit.integrity.brokenAtId} 이후`} |
| 발견사항·승인 기록 대조 | ${ccLabel} |
| 외부 타임스탬프 앵커 | ${anchors.label} |
| 기록 완전성 (git 이력 대조) | ${completeness.label} |
| 승인 행위 서명 (SSH) | ${approvalSigs.label} |

## 요약

- 기간 중 커밋 **${origin.total}건** 기록, 그중 AI 관여가 확인·추정된 커밋 **${origin.confirmed + origin.estimated}건**
- 커밋 시점 보안 검사 **${scans}회**, 발견사항 **${findings.length}건**
- 처리 완료 **${findings.length - unapproved.length}건** (조치 완료 ${fixedCount} · 승인 ${acceptedCount} · 예외 ${exceptions.length}), **미승인 ${unapproved.length}건**${aiUnapproved.length > 0 ? ` — 그중 AI 생성 커밋에서 나온 항목 ${aiUnapproved.length}건` : ""}
- 처리 행위 ${approvals}건이 모두 처리 시점에 원장에 기록됨 (사후 작성 문서가 아님)

## 1. ISMS-P 개발보안 영역 대응 범위 [확인 필요]

이 도구가 **증빙을 만들어 주는 범위와 못 만드는 범위**를 함께 적습니다. 조직·절차
항목은 자동으로 검증할 수 없으므로 별도 문서로 대응해야 합니다.

| 인증기준 (2.8 정보시스템 도입 및 개발 보안) | 이 리포트가 제공하는 근거 | 범위 |
|---|---|---|
| 2.8.1 보안 요구사항 정의 | 적용한 시큐어코딩 점검 기준(룰셋 \`${input.ruleset.version}\`, 해시 고정) | 부분 — 요구사항 정의서 자체는 조직 작성 |
| 2.8.2 보안 요구사항 검토 및 시험 | 커밋 단위 점검 이력, 발견사항, 조치·예외 승인 이력과 시각 (2·3장) | **주요 근거** |
| 2.8.3 시험과 운영 환경 분리 | — | 대상 아님 |
| 2.8.4 시험 데이터 보안 | — | 대상 아님 |
| 2.8.5 소스 프로그램 관리 | 커밋별 변경 파일 해시의 변조 불가 이력, AI 출처 기록 (4·6장) | 부분 — 저장소 접근통제는 별도 |
| 2.8.6 운영환경 이관 | 미승인 항목 현황(이관 전 확인 근거) | 부분 — 이관 승인 절차는 별도 |

> 조항 번호·명칭과 근거 인정 여부는 현직 심사원 검증 전 추정입니다.

## 2. 탐지 및 조치 현황

${findingsTable(findings, audit, origin)}

> 모든 항목의 점검·조치·예외 이력은 위 1장의 **2.8.2(보안 요구사항 검토 및 시험)** 근거입니다.
> "관련 기준" 열은 그와 별도로, 탐지된 취약점 유형이 관련된 인증기준을 참고로 적은 것입니다 [확인 필요].
> 상태: **조치 완료** = 코드를 고쳐 해소(재검사 기록으로 확인되면 커밋을 함께 표기) · **승인** = 위험을 확인하고 수용 · **예외** = 사유를 남기고 보류.

**미승인 항목: ${unapproved.length}건** ${unapproved.length > 0 ? "— 담당자 확인이 필요합니다." : ""}
${
  cc.issues.length > 0
    ? `\n### ❌ 원장과 일치하지 않는 항목\n\n발견사항 DB의 내용이 원장(해시 체인)에 기록된 탐지·처리 내역과 다릅니다. 기록이 사후에 수정됐을 수 있습니다.\n\n${cc.issues.map((i) => `- 발견사항 #${i.findingId}: ${i.message}`).join("\n")}\n`
    : ""
}
## 3. 예외 처리 내역

${
  exceptions.length === 0
    ? "_예외 처리된 항목이 없습니다._"
    : exceptions.map((f) => `- **${f.ruleId}** (${f.file}:${f.line}) — ${f.approvedBy ?? "-"}: ${(f.approvalNote ?? "사유 없음").replace(/\r?\n/g, " ")}`).join("\n")
}

## 4. 출처 추적 요약

이 기간 동안 기록된 커밋 ${origin.total}건의 AI 생성 출처 신뢰도 분포입니다.

| 신뢰도 | 판정 근거 | 건수 | 비율 |
|---|---|---|---|
| 확정 (confirmed) | 개발자가 \`AI-Generated\` 트레일러로 직접 선언 | ${origin.confirmed} | ${pct(origin.confirmed, origin.total)} |
| 추정 (estimated) | AI 도구가 붙인 공동작성자 트레일러(\`Co-Authored-By\`) | ${origin.estimated} | ${pct(origin.estimated, origin.total)} |
| 미상 (unknown) | 신호 없음 — AI 미사용이 아니라 "모름" | ${origin.unknown} | ${pct(origin.unknown, origin.total)} |

${origin.tools.size > 0 ? `도구별: ${[...origin.tools].map(([t, n]) => `${t} ${n}건`).join(", ")}` : ""}

${origin.avgRatio !== null ? `선언된 AI 생성 비율 평균: ${(origin.avgRatio * 100).toFixed(0)}% (선언 ${origin.ratioSamples}건 기준)` : ""}

${origin.signatureKnown > 0 ? `커밋 서명(GPG/SSH): ${origin.signed}/${origin.signatureKnown}건이 서명됨 (${pct(origin.signed, origin.signatureKnown)}). \`actor\`(git 이메일)는 누구나 임의로 설정할 수 있어 신원 근거로는 약합니다 — 서명된 커밋만 "이 키 소유자가 작성"이라는 더 강한 근거를 갖습니다.` : ""}

> 도구가 판단하지 못한 부분("미상")을 숨기지 않고 그대로 표기합니다 — 정확도를
> 과장하지 않는 것이 증빙 자료로서는 더 신뢰할 수 있다는 판단입니다.

## 5. 재현 가능성

${
  sourcesUsed.length <= 1
    ? `이 리포트는 룰셋 버전 \`${sourcesUsed[0].version}\`(hash \`${sourcesUsed[0].hash.slice(0, 16)}…\`)로
고정된 상태에서 생성되었습니다. 같은 커밋 범위에 같은 룰셋 버전으로 다시
생성해도 동일한 결과가 나옵니다 — 생성 시점에 따라 결과가 달라지는 LLM 단독
도구와의 핵심 차이점입니다.`
    : `이 기간에는 서로 다른 탐지 출처 ${sourcesUsed.length}건이 섞여 있습니다 — 전부
같은 룰셋이라고 전제하면 안 됩니다. 각 출처는 독립적으로 고정·재현 가능합니다:

| 출처 | 해시 |
|---|---|
${sourcesUsed.map((s) => `| \`${s.version}\` | \`${s.hash.slice(0, 16)}…\` |`).join("\n")}

\`external:\`로 시작하는 항목은 semgrep이 아니라 \`import-sarif\`로 가져온 외부
도구 결과입니다 — 해시는 우리 룰셋이 아니라 가져온 SARIF 파일 자체의 해시이며,
그 도구의 스캔 로직 자체를 우리가 고정·검증한 것은 아닙니다.`
}

## 6. 기록의 무결성 — 어떻게 믿을 수 있는가

1. **해시 체인**: 모든 기록(커밋·검사·승인)은 앞 기록의 해시를 포함해 연결됩니다.
   중간 기록 하나를 고치면 그 뒤 전체가 어긋나 검출됩니다. 승인 대상·결정·사유도
   체인 안에 들어 있어, 발견사항 DB를 직접 고치면 "발견사항·승인 기록 대조"에서 걸립니다.
2. **외부 타임스탬프 앵커**: 해시 체인은 원장 전체를 처음부터 다시 만드는 것은 막지
   못합니다. 그래서 독립 기관(RFC3161 TSA)이 원장 끝 해시에 서명한 토큰을 보관하고,
   검증 시 그 서명과 지금 원장의 해시를 대조합니다.
3. **승인 행위 서명**: 처리자가 SSH 키로 승인 내용(대상·결정·사유·커밋)에 서명하면,
   git 이메일(누구나 바꿀 수 있음)만이 아니라 "이 키 소유자가 이 내용으로 처리했다"는
   근거가 생깁니다. 서명은 원장 레코드 안에 들어가 해시 체인으로도 보호됩니다.
4. **코드 본문 미저장**: 원장에는 파일 해시와 메타데이터만 있고 소스코드는 없습니다.
   코드 외부 반출 금지 정책을 지키면서 원장을 그대로 제출할 수 있습니다.
5. **기록 완전성**: 1·2는 "있는 기록을 고치지 않았다"만 보장합니다. 커밋 훅을 거치지
   않은 커밋은 애초에 기록이 없으므로, git 이력과 원장을 대조해 빠진 커밋을 따로 찾습니다.

### 외부 타임스탬프 앵커 검증 결과

${anchors.detail}

### 기록 완전성 검사 결과

${completeness.detail}

### 승인 행위 서명 검증 결과

${approvalSigs.detail}

### 알려진 한계

- 서명 없이 기록된 승인은 git 설정의 이메일만 근거로 합니다(자기신고). 서명된 승인도
  "키 소유자가 본인인가"는 허용 서명자 목록을 누가 관리하느냐에 달려 있습니다 —
  SSO 연동 전까지는 그 목록의 관리 책임이 조직에 있습니다.
- 앵커와 앵커 사이 구간은 다음 앵커 전까지 외부 보증이 없습니다. 앵커 주기가 곧 보증 간격입니다.
- 기록 완전성은 이 리포트를 생성한 저장소 사본의 git 이력 기준입니다. 원장은 저장소
  사본마다 따로 쌓이므로, 다른 개발자의 PC에서 만든 커밋은 그 사본의 원장에 기록됩니다
  (팀 단위 원장 통합은 다음 단계).

## 부록. 감독 원장 상세

| # | 종류 | 커밋 | 시각 | 기록자 | 내용 | 레코드 해시 |
|---|---|---|---|---|---|---|
${audit.entries
  .map((e) => {
    const p = e.payload;
    const what =
      p?.kind === "detected"
        ? `검사 — 발견 ${p.findings.length}건`
        : p?.kind === "approved"
          ? `발견사항 #${p.findingId} ${DECISION_LABEL[p.decision]}`
          : `${e.originConfidence}${e.aiTool ? `(${e.aiTool})` : ""}, 파일 ${e.fileHashes.length}개`;
    return `| ${e.id} | ${e.eventType} | ${e.commitHash.slice(0, 8)} | ${shortTime(e.timestamp)} | ${cell(e.actor)} | ${what} | \`${e.hash.slice(0, 16)}…\` |`;
  })
  .join("\n")}
`;
}
