import { execFileSync } from "node:child_process";

/** git log --format=%G?가 주는 1글자 코드. git-log(1) "PRETTY FORMATS" 참고.
 * N(서명 없음)이 기본값 — 대부분의 커밋은 여기 해당한다. */
export type SignatureStatus =
  | "good"
  | "bad"
  | "unknown"
  | "expired"
  | "expiredKey"
  | "revoked"
  | "missingKey"
  | "none";

const STATUS_MAP: Record<string, SignatureStatus> = {
  G: "good",
  B: "bad",
  U: "unknown",
  X: "expired",
  Y: "expiredKey",
  R: "revoked",
  E: "missingKey",
  N: "none",
};

export interface CommitSignature {
  status: SignatureStatus;
  /** GPG/SSH 서명자 이름 — git이 알아낼 수 있을 때만. 미서명이면 null. */
  signer: string | null;
}

/** 커밋이 GPG/SSH로 서명됐는지 git에 직접 물어본다. `git config user.email`은
 * 누구나 아무 값이나 넣을 수 있어서(실제로 approve 커맨드가 그 값을 그대로
 * actor로 쓴다) 신뢰도가 약하다 — 서명이 있으면 "이 사람의 키로 만들어진
 * 커밋이 맞다"는 더 강한 근거가 된다. 서명이 없는 것도(기본값) 솔직하게
 * "none"으로 남긴다 — 없는 걸 있는 척하지 않는다. */
export function getCommitSignature(repoRoot: string, commitHash: string): CommitSignature {
  try {
    // %x1f(unit separator)로 구분 — 서명자 이름에 콤마·공백이 섞여도 안전하게 쪼갠다.
    const out = execFileSync(
      "git",
      ["log", "-1", "--format=%G?%x1f%GS", commitHash],
      { cwd: repoRoot, encoding: "utf-8" }
    ).trim();
    const sep = out.indexOf("\x1f");
    const code = sep === -1 ? out : out.slice(0, sep);
    const signer = sep === -1 ? "" : out.slice(sep + 1);
    return { status: STATUS_MAP[code] ?? "none", signer: signer || null };
  } catch {
    // 커밋을 못 찾거나 git 호출 자체가 실패해도 "서명 없음"으로 안전하게 폴백 —
    // 이 함수가 던지면 post-commit 훅 전체가 막혀 커밋을 방해하게 된다.
    return { status: "none", signer: null };
  }
}
