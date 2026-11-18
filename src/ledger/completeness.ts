import { execFileSync } from "node:child_process";
import type { LedgerEntry } from "./types.js";

/**
 * 완전성 검사 — "기록을 나중에 고치지 않았다"(해시 체인·앵커)와 별개로
 * "기록해야 할 커밋이 빠짐없이 기록됐다"를 확인한다.
 *
 * post-commit 훅은 우회될 수 있다. 직접 확인한 결과(git 2.x):
 * - `commit --no-verify`, `--amend`, cherry-pick, rebase, revert → 훅이 실행된다
 * - `merge --no-ff`로 생긴 병합 커밋 → 훅이 실행되지 않는다 (post-merge만 돈다)
 * - `-c core.hooksPath=...`로 훅 경로를 바꾸거나, 훅을 설치하지 않은 곳에서 만든
 *   커밋 → 기록이 남지 않는다
 *
 * 그래서 git 이력을 기준으로 원장을 대조한다. 원장(체인 안)에 없는 일반 커밋은
 * "훅을 거치지 않고 들어온 커밋"으로 실패 처리하고, 병합 커밋은 원래 훅이 돌지
 * 않으므로 실패가 아닌 "확인 필요"로 따로 센다.
 */

export interface HistoryCommit {
  hash: string;
  parents: string[];
  author: string;
  /** author date (ISO). 작성자가 바꿀 수 있는 값이라 판정에는 쓰지 않고 표시만 한다. */
  date: string;
  subject: string;
}

export interface ScanGap {
  commitHash: string;
  /** 커밋 이후 어떤 검사에도 포함되지 않은 파일 */
  files: string[];
}

export interface CompletenessResult {
  /** 검사 기준 커밋 — 원장에 기록된 가장 오래된 커밋(또는 사용자가 지정한 커밋).
   * 이보다 앞선 커밋은 도구 도입 전이라 대상에서 뺀다. null이면 검사할 범위가 없다. */
  baseline: string | null;
  /** 검사한 일반 커밋 수(병합 커밋 제외) */
  checked: number;
  /** 그중 원장에 커밋 기록이 있는 수 */
  recorded: number;
  /** 원장에 기록이 없는 일반 커밋 — 훅을 거치지 않고 만들어진 커밋 */
  missing: HistoryCommit[];
  /** 원장에 기록이 없는 병합 커밋 — 훅이 원래 돌지 않는 동작이라 실패로 보지 않는다 */
  unrecordedMerges: HistoryCommit[];
  /** 기록은 됐지만 바뀐 파일이 어떤 보안 검사에도 포함되지 않은 커밋 */
  scanGaps: ScanGap[];
  /** 커밋 시점 검사는 없었지만 이후 검사(scan --all 등)에 파일이 모두 포함된 커밋 수 */
  lateScanned: number;
  /** 원장에는 있지만 지금 이력에는 없는 커밋(amend·rebase·reset으로 이력이 바뀐 경우) */
  orphaned: Array<{ commitHash: string; ledgerEntryId: number }>;
}

/** 삭제된 파일은 post-commit 훅이 빈 내용의 해시로 남긴다 — 검사할 대상이 아니다. */
const EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/**
 * git 이력과 원장을 대조한다(순수 함수 — git 호출은 readHistory가 한다).
 *
 * @param history  기준 커밋부터 HEAD까지의 커밋(기준 커밋 포함)
 * @param reachable HEAD에서 닿는 모든 커밋 해시 — 원장에만 있는 커밋을 찾는 데 쓴다
 */
export function checkCompleteness(
  history: HistoryCommit[],
  reachable: Set<string>,
  entries: LedgerEntry[],
  baseline: string | null
): CompletenessResult {
  const generatedByCommit = new Map<string, LedgerEntry>();
  for (const e of entries) {
    if (e.eventType === "generated" && !generatedByCommit.has(e.commitHash)) generatedByCommit.set(e.commitHash, e);
  }
  // 어떤 파일을 봤는지 남긴 검사만 근거로 쓴다(import-sarif처럼 대상 목록이 없는 건 제외).
  const scans = entries.filter((e) => e.payload?.kind === "detected" && e.fileHashes.length > 0);
  const scanned = (scan: LedgerEntry, path: string) => scan.fileHashes.some((h) => h.path === path);

  const result: CompletenessResult = {
    baseline,
    checked: 0,
    recorded: 0,
    missing: [],
    unrecordedMerges: [],
    scanGaps: [],
    lateScanned: 0,
    orphaned: [],
  };

  for (const c of history) {
    const gen = generatedByCommit.get(c.hash);
    if (c.parents.length > 1) {
      if (!gen) result.unrecordedMerges.push(c);
      continue;
    }
    result.checked++;
    if (!gen) {
      result.missing.push(c);
      continue;
    }
    result.recorded++;

    const files = gen.fileHashes.filter((f) => f.hash !== EMPTY_SHA256).map((f) => f.path);
    if (files.length === 0) continue;
    const later = scans.filter((s) => s.id > gen.id);
    const atCommit = later.filter((s) => s.commitHash === c.hash);
    if (files.every((p) => atCommit.some((s) => scanned(s, p)))) continue;

    const never = files.filter((p) => !later.some((s) => scanned(s, p)));
    if (never.length === 0) result.lateScanned++;
    else result.scanGaps.push({ commitHash: c.hash, files: never });
  }

  for (const [commitHash, e] of generatedByCommit) {
    if (!reachable.has(commitHash)) result.orphaned.push({ commitHash, ledgerEntryId: e.id });
  }
  return result;
}

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 256 * 1024 * 1024,
  }).trim();
}

const FIELD = "\x1f";
const LOG_FORMAT = ["%H", "%P", "%an", "%aI", "%s"].join("%x1f");

function parseLog(out: string): HistoryCommit[] {
  return out
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const [hash, parents, author, date, subject] = line.split(FIELD);
      return { hash, parents: parents ? parents.split(" ") : [], author, date, subject: subject ?? "" };
    });
}

/**
 * 대조할 git 이력을 읽는다. 기준 커밋은 따로 주지 않으면 "HEAD 이력 중 원장에
 * 기록된 가장 오래된 커밋"이다 — 도구를 설치하기 전 커밋까지 누락으로 세지 않기 위해서.
 */
export function readHistory(
  repoRoot: string,
  entries: LedgerEntry[],
  since?: string
): { history: HistoryCommit[]; reachable: Set<string>; baseline: string | null } {
  let order: string[];
  try {
    order = git(["rev-list", "--topo-order", "HEAD"], repoRoot).split("\n").filter(Boolean);
  } catch {
    return { history: [], reachable: new Set(), baseline: null }; // 커밋이 하나도 없는 저장소
  }
  const reachable = new Set(order);

  let baseline: string | null = null;
  if (since) {
    baseline = git(["rev-parse", "--verify", `${since}^{commit}`], repoRoot);
  } else {
    const recorded = new Set(entries.filter((e) => e.eventType === "generated").map((e) => e.commitHash));
    for (let i = order.length - 1; i >= 0; i--) {
      if (recorded.has(order[i])) {
        baseline = order[i];
        break;
      }
    }
  }
  if (!baseline) return { history: [], reachable, baseline: null };

  // --no-show-signature: log.showSignature 설정이 켜진 환경에서 서명 정보가 출력에 섞이지 않게.
  const range = parseLog(git(["log", "--no-show-signature", `--format=${LOG_FORMAT}`, `${baseline}..HEAD`], repoRoot));
  const base = parseLog(git(["log", "--no-show-signature", "-1", `--format=${LOG_FORMAT}`, baseline], repoRoot));
  return { history: [...range, ...base], reachable, baseline };
}

export function auditCompleteness(repoRoot: string, entries: LedgerEntry[], since?: string): CompletenessResult {
  const { history, reachable, baseline } = readHistory(repoRoot, entries, since);
  return checkCompleteness(history, reachable, entries, baseline);
}
