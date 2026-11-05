import { test } from "node:test";
import assert from "node:assert/strict";
import { markdownToHtmlBody, renderReportHtml } from "../src/report/html.js";

test("승인 사유 같은 사용자 입력의 HTML은 이스케이프된다", () => {
  const html = markdownToHtmlBody("| 처리자 |\n|---|\n| a@b.c — <script>alert(1)</script> |");
  assert.ok(!html.includes("<script>"));
  assert.ok(html.includes("&lt;script&gt;"));
});

test("표: 이스케이프된 세로선은 칸을 나누지 않는다", () => {
  const html = markdownToHtmlBody("| a | b |\n|---|---|\n| x \\| y | z |");
  assert.ok(html.includes("<td>x | y</td>"));
  assert.equal((html.match(/<td/g) ?? []).length, 2);
});

test("상태 표시는 색 구분 클래스를 받고, 넓은 표는 wide가 된다", () => {
  const md =
    "| 1 | 2 | 3 | 4 | 5 | 6 | 7 |\n|---|---|---|---|---|---|---|\n| ⚠ 미승인 | ❌ 불일치 | ✅ 정상 | - | - | - | - |";
  const html = markdownToHtmlBody(md);
  assert.ok(html.includes('<table class="wide">'));
  assert.ok(html.includes('<td class="warn">'));
  assert.ok(html.includes('<td class="bad">'));
  assert.ok(html.includes('<td class="ok">'));
});

test("발견사항 표(10칸)가 있는 장은 제목째 가로 페이지 묶음이 되고 다음 장에서 닫힌다", () => {
  const row = (c: string) => `| ${Array(10).fill(c).join(" | ")} |`;
  const md = `## 2. 탐지\n\n${row("h")}\n${row("---")}\n${row("x")}\n\n미승인 1건\n\n## 3. 예외\n\n본문`;
  const html = markdownToHtmlBody(md);
  assert.match(html, /<section class="landscape">\n<h2>2\. 탐지<\/h2>\n<table[\s\S]*<p>미승인 1건<\/p>\n<\/section>\n<h2>3\. 예외<\/h2>/);
});

test("들여쓴 줄은 앞 목록 항목에 이어 붙는다", () => {
  const html = markdownToHtmlBody("1. **해시 체인**: 첫 줄\n   둘째 줄\n2. 다음");
  assert.ok(html.includes("<ol><li><strong>해시 체인</strong>: 첫 줄 둘째 줄</li><li>다음</li></ol>"));
});

test("문서 제목은 첫 h1에서 가져온다", () => {
  const html = renderReportHtml("# 리포트 <제목>\n\n본문");
  assert.ok(html.includes("<title>리포트 &lt;제목&gt;</title>"));
  assert.ok(html.startsWith("<!doctype html>"));
});
