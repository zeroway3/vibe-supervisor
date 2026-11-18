#!/usr/bin/env bash
# 보안담당자·심사원 미팅용 시연 스크립트.
# 임시 Java/Spring 저장소를 만들어 "AI가 쓴 코드 커밋 → 커밋 시점 검사 → 수정·승인
# → 외부 타임스탬프 → 리포트 → 변조 시도 → 검출"을 처음부터 끝까지 보여준다.
#
#   npm run build && bash demo/run-demo.sh
#   DEMO_OFFLINE=1 bash demo/run-demo.sh   # TSA(외부 네트워크) 단계를 건너뛴다
#   DEMO_DIR=/path bash demo/run-demo.sh   # 작업 폴더 지정 (기본: 임시 폴더)
#   DEMO_PAUSE=1 bash demo/run-demo.sh     # 단계마다 Enter를 기다린다 (발표용)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# node -e 안의 require 경로는 Git Bash가 바꿔주지 않으므로 Windows 경로로 만든다.
ROOT_NATIVE="$(cygpath -m "$ROOT" 2>/dev/null || echo "$ROOT")"
VS="node $ROOT/dist/cli/index.js"
SAMPLE="$ROOT/demo/sample-spring"
WORK="${DEMO_DIR:-$(mktemp -d)}"
REPO="$WORK/payment-service"

if [ ! -f "$ROOT/dist/cli/index.js" ]; then
  echo "먼저 'npm run build'를 실행하세요." >&2
  exit 1
fi

step() {
  echo
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "▶ $1"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  if [ "${DEMO_PAUSE:-}" = "1" ]; then read -r -p "(Enter) " _; fi
}

# 첫 승인 대상(가장 앞 번호의 미승인 발견사항) 중 규칙 ID가 맞는 것의 번호를 찾는다.
finding_id() {
  node -e "
    const D = require('$ROOT_NATIVE/node_modules/better-sqlite3');
    const db = new D(process.argv[1], { readonly: true });
    const r = db.prepare(\"SELECT id FROM findings WHERE rule_id = ? AND status = 'open' ORDER BY id LIMIT 1\").get(process.argv[2]);
    console.log(r ? r.id : '');
  " "$REPO/.vibe-supervisor/findings.db" "$1"
}

rm -rf "$REPO"
mkdir -p "$REPO"
cd "$REPO"
git init -q
git config user.name "김개발"
git config user.email "dev@example-corp.co.kr"
echo ".vibe-supervisor/" > .gitignore
echo "*.md" >> .gitignore

step "1. 설치 — git 훅 하나만 연결합니다. 개발자는 평소대로 커밋만 하면 됩니다."
$VS install

step "2. AI(claude-code)가 작성한 코드를 커밋 — 커밋 시점에 바뀐 파일만 자동 검사"
cp -r "$SAMPLE/v1/." .
git add -A
git commit -q -m "feat: 사용자 조회·결제 승인·세션 토큰 추가

AI-Generated: claude-code, ratio=0.8"

step "3. 개발자가 SQL 인젝션을 PreparedStatement로 수정 (AI 도구가 공동작성자로 자동 표기 → '추정')"
cp -r "$SAMPLE/v2/." .
git add -A
git commit -q -m "fix: 사용자 조회 쿼리를 PreparedStatement로 변경

Co-Authored-By: Claude <noreply@anthropic.com>"

step "4. 보안 담당자가 발견사항을 처리 — 처리 행위 자체가 원장에 남습니다"
SQL_ID="$(finding_id ko-baseline.sql-string-concat)"
RAND_ID="$(finding_id ko-baseline.weak-random-for-security)"
if [ -n "$SQL_ID" ]; then
  git config user.email "security@example-corp.co.kr"
  $VS approve "$SQL_ID" --fixed --note "PreparedStatement로 수정 (커밋 $(git rev-parse --short HEAD))"
fi
if [ -n "$RAND_ID" ]; then
  $VS approve "$RAND_ID" --exception --note "내부 로그 상관관계 ID 용도, 인증에 쓰지 않음 — 다음 분기 재검토"
fi
git config user.email "dev@example-corp.co.kr"
echo "(하드코딩된 결제 API 키는 일부러 미승인으로 남겨 둡니다)"

if [ "${DEMO_OFFLINE:-}" != "1" ]; then
  step "5. 원장 끝 해시를 외부 타임스탬프 기관(TSA)에 등록 — 소급 재생성 방지"
  $VS anchor || echo "(TSA 연결 실패 — 오프라인 시연이면 DEMO_OFFLINE=1로 실행하세요)"
fi

step "6. 원장 확인"
$VS log

step "7. 검증 — 체인 / 발견사항·승인 대조 / 외부 앵커 서명 / 기록 완전성(빠진 커밋)"
$VS verify

step "8. 심사 제출용 리포트 생성"
$VS report -o "$REPO/report.md"
$VS report -o "$REPO/report.html"
echo "리포트: $REPO/report.md"
echo "인쇄용: $REPO/report.html (브라우저에서 열고 '인쇄 / PDF로 저장')"

# 이하 변조 시나리오는 원본을 건드리지 않도록 복사본에서 한다.
# expect_detected=0인 경우(DEMO_OFFLINE이라 앵커가 없을 때의 9-c)는 "미검출"이
# 버그가 아니라 앵커 없이는 원래 못 잡는다는 걸 보여주는 의도된 결과다 — 그걸
# "검출 실패"라고만 찍으면 발표 중 버그처럼 보인다.
attack() {
  local name="$1" mode="$2" expect_detected="${3:-1}"
  local copy="$WORK/attack-$mode"
  rm -rf "$copy"
  cp -r "$REPO" "$copy"
  step "$name"
  node "$ROOT/demo/tamper.mjs" "$copy" "$mode"
  if (cd "$copy" && $VS verify); then
    if [ "$expect_detected" = "1" ]; then
      echo "!! 검출 실패 (예상과 다릅니다 — 버그일 수 있습니다)"
    else
      echo "→ (예상된 결과) 미검출 — 앵커가 없는 구간은 외부 보증이 없어 이 공격을 못 잡습니다."
      echo "   DEMO_OFFLINE 없이(실제 TSA에 등록하고) 실행하면 anchor가 이 공격을 잡아냅니다."
    fi
  else
    echo "→ 검출됨 (verify 실패, exit 1)"
  fi
}

attack "9-a. 공격: 승인 사유를 DB에서 몰래 고치기" findings-note
attack "9-b. 공격: 미승인 항목을 원장 없이 '승인'으로 바꾸기" fake-approval
if [ "${DEMO_OFFLINE:-}" = "1" ]; then
  attack "9-c. 공격: 원장 전체를 다시 계산해 AI 생성 이력 지우기 (+앵커 해시까지 수정)" rewrite-chain 0
else
  attack "9-c. 공격: 원장 전체를 다시 계산해 AI 생성 이력 지우기 (+앵커 해시까지 수정)" rewrite-chain 1
fi

echo
echo "시연 끝. 작업 폴더: $WORK"
