/**
 * 커밋 메시지에서 "AI-Generated: <tool>[, ratio=<0~1>]" 트레일러를 찾는다.
 * 예: "AI-Generated: claude-code, ratio=0.7"
 * 트레일러가 없으면 출처를 모른다는 뜻이므로 confidence는 "unknown"이 된다 —
 * 이게 1단계(커밋 트레일러 방식)의 본질적 한계이고, 2단계(IDE 확장 이벤트
 * 캡처)가 풀어야 하는 문제다.
 */
export interface TrailerResult {
  aiTool: string | null;
  confidence: "confirmed" | "unknown";
}

const TRAILER_PATTERN = /^AI-Generated:\s*([a-zA-Z0-9_-]+)(?:,\s*ratio=([0-9.]+))?\s*$/m;

export function parseAiTrailer(commitMessage: string): TrailerResult {
  const match = commitMessage.match(TRAILER_PATTERN);
  if (!match) {
    return { aiTool: null, confidence: "unknown" };
  }
  return { aiTool: match[1], confidence: "confirmed" };
}
