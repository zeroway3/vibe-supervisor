/**
 * 커밋 메시지에서 AI 출처 신호를 찾는다. 신뢰도는 3단계다.
 *
 * - confirmed: 개발자가 "AI-Generated: <tool>[, ratio=<0~1>]" 트레일러로 직접
 *   선언한 경우. 예: "AI-Generated: claude-code, ratio=0.7"
 * - estimated: 선언은 없지만 AI 코딩 도구가 스스로 붙이는 공동작성자
 *   트레일러(예: "Co-Authored-By: Claude ...", Copilot·Cursor·Aider 등)가 있는
 *   경우. 도구가 붙인 흔적이라 AI가 관여한 건 거의 확실하지만, 개발자가 얼마나
 *   고쳤는지(비율)는 알 수 없고 개발자가 지우거나 남길 수도 있어서 "추정"으로 둔다.
 * - unknown: 아무 신호도 없음. AI를 안 썼다는 뜻이 아니라 모른다는 뜻이다 —
 *   이게 커밋 트레일러 방식의 본질적 한계이고, IDE 확장 이벤트 캡처가 풀어야
 *   하는 문제다.
 */
export interface TrailerResult {
  aiTool: string | null;
  /** AI-Generated 트레일러의 ratio. 0~1 범위를 벗어나거나 없으면 null. */
  aiRatio: number | null;
  confidence: "confirmed" | "estimated" | "unknown";
  originSource: "ai-generated-trailer" | "co-author-trailer" | "none";
}

const TRAILER_PATTERN = /^AI-Generated:\s*([a-zA-Z0-9_-]+)(?:,\s*ratio=([0-9.]+))?\s*$/m;

const CO_AUTHOR_PATTERN = /^Co-Authored-By:\s*(.+)$/gim;

// 공동작성자 이름/메일에 이 키워드가 들어 있으면 AI 도구로 본다.
const AI_CO_AUTHORS: Array<{ match: RegExp; tool: string }> = [
  { match: /claude|anthropic/i, tool: "claude" },
  { match: /copilot/i, tool: "copilot" },
  { match: /cursor/i, tool: "cursor" },
  { match: /aider/i, tool: "aider" },
  { match: /codex|openai/i, tool: "codex" },
  { match: /gemini/i, tool: "gemini" },
  { match: /devin/i, tool: "devin" },
];

export function parseAiTrailer(commitMessage: string): TrailerResult {
  const match = commitMessage.match(TRAILER_PATTERN);
  if (match) {
    const ratio = match[2] !== undefined ? Number(match[2]) : NaN;
    return {
      aiTool: match[1],
      aiRatio: Number.isFinite(ratio) && ratio >= 0 && ratio <= 1 ? ratio : null,
      confidence: "confirmed",
      originSource: "ai-generated-trailer",
    };
  }

  for (const m of commitMessage.matchAll(CO_AUTHOR_PATTERN)) {
    const hit = AI_CO_AUTHORS.find((a) => a.match.test(m[1]));
    if (hit) {
      return { aiTool: hit.tool, aiRatio: null, confidence: "estimated", originSource: "co-author-trailer" };
    }
  }

  return { aiTool: null, aiRatio: null, confidence: "unknown", originSource: "none" };
}
