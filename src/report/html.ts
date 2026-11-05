// 마크다운 리포트를 인쇄용 HTML 한 파일로 바꾼다. 보안담당자·심사원은 리포트를
// 브라우저나 출력물(PDF)로 보기 때문에, .md 그대로는 표가 기호로 보이거나 A4에서
// 잘린다. 외부 라이브러리 없이 generate.ts가 만드는 문법(제목·표·인용·목록·
// 굵게·코드)만 처리한다 — 폐쇄망 설치에서 의존성을 늘리지 않기 위해서다.
//
// 승인 사유처럼 사용자가 입력한 문자열이 그대로 들어오므로, 서식을 입히기 전에
// 반드시 HTML 이스케이프부터 한다.

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function inline(text: string): string {
  return escapeHtml(text)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/^_(.+)_$/, "<em>$1</em>");
}

/** 표 칸 나누기 — `\|`는 칸 구분자가 아니라 내용 안의 세로선이다. */
function splitRow(line: string): string[] {
  const body = line.trim().replace(/^\|/, "").replace(/\|$/, "");
  return body.split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, "|"));
}

/** 상태 표시를 색으로도 구분한다. 흑백 인쇄에서는 기호·글자가 그대로 남는다. */
function cellClass(text: string): string {
  if (text.includes("❌")) return ' class="bad"';
  if (text.includes("⚠")) return ' class="warn"';
  if (text.includes("✅")) return ' class="ok"';
  return "";
}

function renderTable(lines: string[]): string {
  const [head, , ...rows] = lines;
  const headers = splitRow(head);
  const cls = headers.length >= 7 ? "wide" : headers.length === 2 ? "kv" : "";
  const th = headers.map((h) => `<th>${inline(h)}</th>`).join("");
  const tr = rows
    .map((r) => `<tr>${splitRow(r).map((c) => `<td${cellClass(c)}>${inline(c)}</td>`).join("")}</tr>`)
    .join("\n");
  return `<table${cls ? ` class="${cls}"` : ""}><thead><tr>${th}</tr></thead><tbody>\n${tr}\n</tbody></table>`;
}

const LANDSCAPE_COLUMNS = 10;

export function markdownToHtmlBody(md: string): string {
  const lines = md.replace(/\r\n/g, "\n").split("\n");
  const out: string[] = [];
  let i = 0;
  // 칸이 아주 많은 표(발견사항 표)가 있는 장은 인쇄 시 가로 페이지로 뺀다.
  // 장 제목부터 다음 장 제목 전까지를 한 묶음으로 감싼다.
  let inLandscape = false;
  const closeLandscape = () => {
    if (inLandscape) out.push("</section>");
    inLandscape = false;
  };

  while (i < lines.length) {
    const line = lines[i];

    if (line.trim() === "") {
      i++;
      continue;
    }

    const h = line.match(/^(#{1,3}) (.*)$/);
    if (h) {
      const level = h[1].length;
      if (level <= 2) closeLandscape();
      out.push(`<h${level}${cellClass(h[2])}>${inline(h[2])}</h${level}>`);
      i++;
      continue;
    }

    if (line.startsWith("|")) {
      const block: string[] = [];
      while (i < lines.length && lines[i].startsWith("|")) block.push(lines[i++]);
      if (!inLandscape && splitRow(block[0]).length >= LANDSCAPE_COLUMNS) {
        // 바로 앞이 장 제목이면 제목도 같은 가로 페이지로 데려간다.
        const prev = out[out.length - 1];
        const heading = prev?.startsWith("<h2") ? out.pop()! : null;
        out.push('<section class="landscape">');
        if (heading) out.push(heading);
        inLandscape = true;
      }
      out.push(renderTable(block));
      continue;
    }

    if (line.startsWith(">")) {
      const block: string[] = [];
      while (i < lines.length && lines[i].startsWith(">")) block.push(lines[i++].replace(/^> ?/, ""));
      out.push(`<blockquote${cellClass(block.join(" "))}><p>${inline(block.join(" "))}</p></blockquote>`);
      continue;
    }

    const listMatch = line.match(/^(- |\d+\. )/);
    if (listMatch) {
      const ordered = listMatch[1] !== "- ";
      const items: string[] = [];
      while (i < lines.length) {
        const l = lines[i];
        const m = l.match(/^(- |\d+\. )(.*)$/);
        if (m && (m[1] !== "- ") === ordered) {
          items.push(m[2]);
        } else if (/^\s+\S/.test(l) && items.length > 0) {
          // 들여쓴 줄은 앞 항목의 이어지는 문장이다.
          items[items.length - 1] += " " + l.trim();
        } else {
          break;
        }
        i++;
      }
      const tag = ordered ? "ol" : "ul";
      out.push(`<${tag}>${items.map((it) => `<li>${inline(it)}</li>`).join("")}</${tag}>`);
      continue;
    }

    const para: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() !== "" &&
      !/^(#{1,3} |\||>|- |\d+\. )/.test(lines[i])
    ) {
      para.push(lines[i++].trim());
    }
    out.push(`<p>${inline(para.join(" "))}</p>`);
  }

  closeLandscape();
  return out.join("\n");
}

const STYLE = `
:root { color-scheme: light; }
* { box-sizing: border-box; }
body {
  margin: 0; background: #f3f4f6; color: #111827;
  font-family: "Malgun Gothic", "Apple SD Gothic Neo", "Noto Sans KR", sans-serif;
  font-size: 10.5pt; line-height: 1.55;
}
main { max-width: 210mm; margin: 24px auto; padding: 18mm 16mm; background: #fff; box-shadow: 0 1px 4px rgba(0,0,0,.12); }
h1 { font-size: 17pt; margin: 0 0 12px; padding-bottom: 8px; border-bottom: 2px solid #111827; }
h2 { font-size: 13pt; margin: 26px 0 8px; padding-bottom: 4px; border-bottom: 1px solid #d1d5db; }
h3 { font-size: 11pt; margin: 18px 0 6px; }
p, ul, ol { margin: 6px 0; }
li { margin: 2px 0; }
code { font-family: Consolas, "D2Coding", monospace; font-size: .9em; background: #f3f4f6; padding: 0 3px; border-radius: 3px; overflow-wrap: anywhere; }
blockquote { margin: 10px 0; padding: 8px 12px; border-left: 4px solid #9ca3af; background: #f9fafb; color: #374151; }
blockquote.warn { border-left-color: #d97706; background: #fffbeb; }
table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 9.5pt; }
th, td { border: 1px solid #d1d5db; padding: 4px 6px; text-align: left; vertical-align: top; }
th { background: #f3f4f6; font-weight: bold; }
table.kv th:first-child, table.kv td:first-child { width: 32%; background: #f9fafb; font-weight: bold; }
table.wide { font-size: 8pt; }
table.wide th { white-space: nowrap; }
table.wide td { overflow-wrap: anywhere; }
/* 번호·심각도·커밋·시각·상태처럼 짧은 칸은 줄바꿈하지 않는다 — 좁은 A4 폭에서
   글자 단위로 쪼개지면 읽을 수 없다. 남는 폭은 파일 경로·사유 칸이 가져간다. */
table.wide td:nth-child(1), table.wide td:nth-child(3), table.wide td:nth-child(8) { white-space: nowrap; }
/* 시각 칸은 날짜와 시각 사이 공백에서만 줄을 바꾼다. */
table.wide td:nth-child(7), table.wide td:nth-child(9) { overflow-wrap: normal; }
td.ok, h1.ok { color: #047857; }
td.warn { color: #b45309; font-weight: bold; }
td.bad { color: #b91c1c; font-weight: bold; }
.toolbar { max-width: 210mm; margin: 16px auto 0; text-align: right; }
.toolbar button { font: inherit; padding: 6px 14px; border: 1px solid #9ca3af; border-radius: 4px; background: #fff; cursor: pointer; }
@page { size: A4; margin: 14mm 12mm; }
@page landscape { size: A4 landscape; margin: 12mm 12mm; }
@media print {
  .landscape { page: landscape; }
  .landscape table.wide { font-size: 8.5pt; }
  .landscape table.wide td:nth-child(7), .landscape table.wide td:nth-child(9) { white-space: nowrap; }
  body { background: #fff; font-size: 9.5pt; }
  main { margin: 0; padding: 0; max-width: none; box-shadow: none; }
  .toolbar { display: none; }
  h2, h3 { break-after: avoid; }
  tr, blockquote, li { break-inside: avoid; }
  thead { display: table-header-group; }
  td.ok, td.warn, td.bad, th { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
`;

/** generateReport()가 만든 마크다운을 그대로 받아 인쇄용 HTML 문서로 감싼다.
 * 브라우저에서 열고 인쇄 → "PDF로 저장"하면 제출용 PDF가 된다. */
export function renderReportHtml(md: string): string {
  const title = md.match(/^# (.*)$/m)?.[1] ?? "개발보안 감독 리포트";
  return `<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>${STYLE}</style>
</head>
<body>
<div class="toolbar"><button type="button" onclick="window.print()">인쇄 / PDF로 저장</button></div>
<main>
${markdownToHtmlBody(md)}
</main>
</body>
</html>
`;
}
