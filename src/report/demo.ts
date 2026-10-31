#!/usr/bin/env node
// 심사원 인터뷰용 샘플 리포트를 생성한다. 실제 고객 데이터가 없으므로
// 현실적인 가짜 커밋 이력을 임시 원장에 채워 넣고 그걸로 리포트를 뽑는다.
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ledger } from "../ledger/db.js";
import { generateReport } from "./generate.js";
import type { Finding } from "./types.js";

const tmpDir = mkdtempSync(join(tmpdir(), "vs-demo-"));
const ledger = new Ledger(join(tmpDir, "ledger.db"));

const sampleCommits: Array<{
  file: string;
  aiTool: string | null;
  confidence: "confirmed" | "estimated" | "unknown";
}> = [
  { file: "src/payment/PaymentController.java", aiTool: "claude-code", confidence: "confirmed" },
  { file: "src/payment/PaymentService.java", aiTool: "claude-code", confidence: "confirmed" },
  { file: "src/auth/TokenValidator.java", aiTool: null, confidence: "unknown" },
  { file: "src/auth/SessionManager.java", aiTool: "copilot", confidence: "estimated" },
  { file: "src/order/OrderRepository.java", aiTool: "claude-code", confidence: "confirmed" },
  { file: "src/order/OrderController.java", aiTool: null, confidence: "unknown" },
  { file: "src/common/InputSanitizer.java", aiTool: "copilot", confidence: "estimated" },
];

for (const c of sampleCommits) {
  ledger.append({
    eventType: "generated",
    commitHash: createHash("sha1").update(c.file + Date.now() + Math.random()).digest("hex"),
    actor: "dev@example-corp.co.kr",
    aiTool: c.aiTool,
    originConfidence: c.confidence,
    fileHashes: [{ path: c.file, hash: createHash("sha256").update(c.file).digest("hex") }],
  });
}

const entries = ledger.all();
const integrity = ledger.verify();
ledger.close();

const rulesetHash = createHash("sha256").update("ko-regulatory-ruleset-v1").digest("hex");

const findings: Finding[] = [
  {
    ruleId: "java.spring.security.hardcoded-secret",
    severity: "critical",
    file: "src/payment/PaymentService.java",
    line: 42,
    message: "결제 API 키가 소스코드에 하드코딩되어 있습니다.",
    ismspClause: "2.8.4 (암호화 적용) [확인 필요]",
    status: "approved",
    approvedBy: "김보안",
    approvalNote: "환경변수로 이관 완료, PR #214 반영",
  },
  {
    ruleId: "java.spring.injection.sql-injection",
    severity: "high",
    file: "src/order/OrderRepository.java",
    line: 118,
    message: "문자열 결합으로 생성된 쿼리에서 SQL 인젝션 가능성이 있습니다.",
    ismspClause: "2.8.1 (보안 요구사항 정의) [확인 필요]",
    status: "exception",
    approvedBy: "박개발",
    approvalNote: "내부망 전용 배치 작업, 외부 입력 경로 없음 — 다음 분기 재검토 예정",
  },
  {
    ruleId: "java.lang.security.weak-random",
    severity: "medium",
    file: "src/auth/SessionManager.java",
    line: 77,
    message: "세션 토큰 생성에 암호학적으로 안전하지 않은 난수 생성기를 사용합니다.",
    ismspClause: "2.8.4 (암호화 적용) [확인 필요]",
    status: "open",
  },
];

const report = generateReport(
  {
    repoName: "example-corp/payment-service (샘플)",
    periodStart: "2026-09-01",
    periodEnd: "2026-09-30",
    ruleset: { version: "ko-regulatory-v1.2", hash: rulesetHash },
    findings,
    isSample: true,
  },
  entries,
  integrity
);

const outPath = join(process.cwd(), "sample-report.md");
writeFileSync(outPath, report);
console.log(`샘플 리포트 생성 완료: ${outPath}`);
