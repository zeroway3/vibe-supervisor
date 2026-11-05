#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Ledger } from "../ledger/db.js";
import { parseAiTrailer } from "../trailer/parse.js";
import { isSemgrepAvailable, scanAndRecord } from "../scan/run.js";
import { FindingsStore } from "../findings/store.js";
import { rescanEvidence } from "../ledger/rescan.js";
import type { FileHash, LedgerEntry } from "../ledger/types.js";
import { loadConfig } from "../config/store.js";
import { AnchorStore } from "../timestamp/store.js";
import { requestTimestamp } from "../timestamp/rfc3161.js";

/** 이번 검사에서 더는 나오지 않은 기존 미승인 항목을 알려준다. 상태는 자동으로 바꾸지
 * 않는다 — "고쳤다"는 판단은 사람이 --fixed로 기록해야 원장의 의미가 산다. */
function reportResolvedByThisScan(repoRoot: string, commitHash: string) {
  const dir = join(repoRoot, ".vibe-supervisor");
  const ledger = new Ledger(join(dir, "ledger.db"));
  const entries = ledger.all();
  ledger.close();
  const store = new FindingsStore(join(dir, "findings.db"));
  const open = store.all().filter((f) => f.status === "open");
  store.close();

  const evidence = rescanEvidence(entries, open);
  const resolved = open.filter((f) => evidence.get(f.id)?.commitHash === commitHash);
  if (resolved.length === 0) return;
  console.log(`[vibe-supervisor] 이번 재검사에서 더는 나오지 않은 기존 발견사항 ${resolved.length}건:`);
  for (const f of resolved) console.log(`  #${f.id} ${f.ruleId}  ${f.file}`);
  console.log("  → 고친 것이 맞다면 'vibe-supervisor approve <번호> --fixed --note \"조치 내용\"'으로 기록하세요.");
}

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const RULESET_PATH = join(__dirname, "..", "..", "rulesets", "ko-baseline-v1.yaml");

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf-8" }).trim();
}

/** 조건(커밋 N건 또는 N시간 경과)이 차면 자동으로 앵커링한다. 네트워크가
 * 느리거나 끊겨 있어도 커밋 자체를 막으면 안 되므로 타임아웃을 걸고,
 * 실패하면 경고만 찍고 조용히 넘어간다 — 조건은 그대로 남아 다음 커밋에서
 * 다시 시도된다. */
async function maybeAutoAnchor(repoRoot: string, allEntries: LedgerEntry[]) {
  const vsDir = join(repoRoot, ".vibe-supervisor");
  const config = loadConfig(join(vsDir, "config.json"));
  if (!config.autoAnchor.enabled || allEntries.length === 0) return;

  const anchorStore = new AnchorStore(join(vsDir, "anchors.db"));
  const anchors = anchorStore.all();
  const latest = anchors[anchors.length - 1];

  const commitsSinceAnchor = latest
    ? allEntries.filter((e) => e.id > latest.ledgerEntryId).length
    : allEntries.length;
  // 앵커가 한 번도 없었다면 기준 시각이 없다 — latest.anchoredAt 대신 원장의
  // 첫 기록 시각을 기준으로 삼는다. (여기서 Infinity를 쓰면 maxAgeHours 조건이
  // 앵커가 없는 동안 항상 참이 되어 everyNCommits 설정과 무관하게 첫 커밋부터
  // 바로 앵커링되는 버그가 생긴다 — 실제로 재현해서 확인함.)
  const referenceTime = latest ? latest.anchoredAt : allEntries[0].timestamp;
  const hoursSinceAnchor = (Date.now() - new Date(referenceTime).getTime()) / 3_600_000;

  const due =
    commitsSinceAnchor >= config.autoAnchor.everyNCommits ||
    hoursSinceAnchor >= config.autoAnchor.maxAgeHours;

  if (!due) {
    anchorStore.close();
    return;
  }

  const tip = allEntries[allEntries.length - 1];
  console.log(
    `[vibe-supervisor] 자동 앵커링 조건 충족(커밋 ${commitsSinceAnchor}건 경과) — ` +
      `${config.autoAnchor.tsaUrl}에 요청 중...`
  );

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.autoAnchor.timeoutMs);
  try {
    const result = await requestTimestamp(
      Buffer.from(tip.hash, "utf-8"),
      config.autoAnchor.tsaUrl,
      controller.signal
    );
    const saved = anchorStore.save({
      ledgerEntryId: tip.id,
      anchoredHash: tip.hash,
      tsaUrl: config.autoAnchor.tsaUrl,
      genTime: result.genTime,
      serialNumber: result.serialNumberHex,
      tokenDer: result.tokenDer,
    });
    console.log(`[vibe-supervisor] 자동 앵커 #${saved.id} 저장 완료 (${result.genTime})`);
  } catch (err: any) {
    console.warn(
      `[vibe-supervisor] 자동 앵커링 실패 — 다음 커밋에서 재시도합니다: ${err.message}`
    );
  } finally {
    clearTimeout(timer);
    anchorStore.close();
  }
}

async function main() {
  const repoRoot = git(["rev-parse", "--show-toplevel"], process.cwd());
  const commitHash = git(["rev-parse", "HEAD"], repoRoot);
  const commitMessage = git(["log", "-1", "--pretty=%B", commitHash], repoRoot);
  const actor = git(["config", "user.email"], repoRoot) || "unknown";

  // --root: 부모가 없는 첫 커밋(root commit)도 빈 트리와 비교해 변경 파일로
  // 잡아낸다. 이게 없으면 저장소의 첫 커밋이 항상 "파일 0개"로 기록된다.
  const changedFiles = git(
    ["diff-tree", "--no-commit-id", "--name-only", "-r", "--root", commitHash],
    repoRoot
  )
    .split("\n")
    .filter(Boolean);

  // MVP: 파일 전체 내용의 sha256. 실제 AI 생성 구간(byte range)만 잡아내는
  // 건 출처 추적이 트레일러 단계를 넘어선 뒤에 할 일 — 지금은 "이 커밋에서
  // 이 파일이 이 상태였다"는 사실만 변조 불가능하게 남기는 게 목표다.
  // 삭제된 파일은 내용이 없으므로 빈 내용의 해시로 남긴다. 그 외 파일을 읽다
  // 실패하면 빈 해시로 넘어가지 않고 그대로 실패시킨다 — 틀린 해시가 원장에
  // 조용히 들어가는 쪽이 기록이 빠지는 것보다 나쁘다.
  const existingFiles = new Set(
    git(["diff-tree", "--no-commit-id", "--name-only", "-r", "--root", "--diff-filter=d", commitHash], repoRoot)
      .split("\n")
      .filter(Boolean)
  );
  const fileHashes: FileHash[] = changedFiles.map((path) => {
    // cat-file은 git show와 달리 작업 트리 경로를 확인하지 않는다(Windows 긴 경로
    // 오류 회피). 바이너리 파일도 있으므로 문자열로 바꾸지 않고 바이트 그대로 해시한다.
    const content = existingFiles.has(path)
      ? execFileSync("git", ["cat-file", "blob", `${commitHash}:${path}`], { cwd: repoRoot, maxBuffer: 256 * 1024 * 1024 })
      : Buffer.alloc(0);
    return { path, hash: createHash("sha256").update(content).digest("hex") };
  });

  const { aiTool, aiRatio, confidence, originSource } = parseAiTrailer(commitMessage);

  const dbPath = join(repoRoot, ".vibe-supervisor", "ledger.db");
  const ledger = new Ledger(dbPath);
  const entry = ledger.append({
    eventType: "generated",
    commitHash,
    actor,
    aiTool,
    originConfidence: confidence,
    fileHashes,
    payload: { kind: "generated", aiRatio, originSource },
  });
  const allEntries = ledger.all();
  ledger.close();

  console.log(
    `[vibe-supervisor] 커밋 ${commitHash.slice(0, 8)} 기록 완료 — ` +
      `출처: ${confidence}${aiTool ? ` (${aiTool}${aiRatio !== null ? `, ratio=${aiRatio}` : ""})` : ""}, ` +
      `파일 ${fileHashes.length}개, 원장 #${entry.id}`
  );

  // 커밋 시점 증분 검사 — 바뀐 파일만 본다(전체 검사는 느려서 개발자가 꺼버린다).
  // semgrep이 없거나 VS_SKIP_SCAN=1이면 건너뛰고, 나중에 'scan'으로 돌릴 수 있다.
  // 삭제된 파일은 검사 대상에서 뺀다.
  const scanTargets = [...existingFiles];
  if (process.env.VS_SKIP_SCAN !== "1" && scanTargets.length > 0) {
    if (!isSemgrepAvailable()) {
      console.log("[vibe-supervisor] semgrep이 없어 커밋 시점 검사는 건너뜁니다 — 설치 후 'vibe-supervisor scan'으로 검사할 수 있습니다.");
    } else {
      try {
        const { findings } = scanAndRecord(repoRoot, RULESET_PATH, commitHash, actor, scanTargets);
        const open = findings.filter((f) => f.status === "open");
        if (open.length === 0) {
          console.log("[vibe-supervisor] 검사 완료 — 새 발견사항 없음.");
          reportResolvedByThisScan(repoRoot, commitHash);
        } else {
          console.log(
            `[vibe-supervisor] 검사 완료 — 미승인 발견사항 ${open.length}건` +
              `${confidence !== "unknown" ? ` (AI 생성 커밋: ${aiTool})` : ""}:`
          );
          for (const f of open) {
            console.log(`  #${f.id} [${f.severity}] ${f.ruleId}  ${f.file}:${f.line}`);
          }
          console.log("  → 'vibe-supervisor approve <번호> [--fixed | --exception] --note \"내용\"'으로 처리하세요.");
          reportResolvedByThisScan(repoRoot, commitHash);
        }
      } catch (err: any) {
        // 훅에서 검사 실패로 커밋 흐름을 막지 않는다 — 기록은 이미 남았다.
        console.error(`[vibe-supervisor] 커밋 시점 검사 실패 (기록은 남음): ${err.message}`);
      }
    }
  }

  // 검사와 별개 관심사 — 검사가 건너뛰어지거나 실패해도 자동 앵커링은 그대로 시도한다.
  await maybeAutoAnchor(repoRoot, allEntries);
}

main().catch((err) => {
  // 훅이 실패해도 커밋 자체는 이미 끝난 뒤이므로, 로그만 남기고 exit code는
  // 0으로 유지한다(여기서 예외를 그대로 던지면 git이 경고를 출력함).
  console.error(`[vibe-supervisor] post-commit 훅 오류: ${err.message}`);
});
