/**
 * Semgrep 룰의 OWASP 태그를 ISMS-P 영역명으로 대략 매핑한다. 전부 report/types.ts의
 * Finding.ismspClause 주석과 같은 이유로 "[확인 필요]"를 붙인다 — 실제 심사
 * 기준 고시와 대조해 재확인하기 전까지는 법적/심사 근거로 인용하면 안 된다.
 * (Q4-1의 "현직 ISMS-P 심사원 3인 인터뷰"가 바로 이 매핑을 검증하는 단계.)
 */
// 위에서부터 먼저 맞는 것을 쓴다 — 구체적인 CWE를 OWASP 대분류보다 앞에 둔다.
// 여기 값은 "취약점 유형이 관련된 기준"이다. 점검·조치 이력 자체의 근거 조항(2.8.2)과는
// 별개라서, 리포트는 둘을 다른 열·다른 장으로 나눠 적는다. 시큐어코딩 결함처럼 별도
// 영역이 없는 유형은 점검 조항(2.8.2)으로 둔다 — 2.8.1(요구사항 정의)로 두면 리포트 1장과 어긋난다.
const OWASP_TO_ISMSP: Array<{ match: RegExp; clause: string }> = [
  { match: /CWE-798/i, clause: "2.7.2 암호키 관리" },
  { match: /A02:2021.*Cryptographic/i, clause: "2.7.1 암호정책 적용" },
  { match: /A03:2021.*Injection/i, clause: "2.8.2 보안 요구사항 검토 및 시험(시큐어코딩 점검)" },
  { match: /A01:2021.*Broken Access Control/i, clause: "2.6 접근통제" },
  { match: /A07:2021.*Identification/i, clause: "2.5 인증 및 권한관리" },
  { match: /A09:2021.*Logging/i, clause: "2.9 시스템 및 서비스 운영관리(로그)" },
];

export function mapToIsmspClause(owaspTags: string[]): string {
  for (const tag of owaspTags) {
    const hit = OWASP_TO_ISMSP.find((m) => m.match.test(tag));
    if (hit) return `${hit.clause} [확인 필요]`;
  }
  return "미분류 — 수동 매핑 필요 [확인 필요]";
}
