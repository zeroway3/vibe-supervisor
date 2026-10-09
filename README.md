# vibe-supervisor

AI 생성 코드에 대한 감독 계층. 탐지 정확도로 경쟁하지 않고, "이 코드는 누가
만들었고 누가 확인했는가"를 변조 불가능한 기록(Supervision Ledger)으로 남긴다.

## 현재 범위 (1단계 — 커밋 트레일러 방식)

- 커밋 메시지의 `AI-Generated: <tool>[, ratio=<0~1>]` 트레일러를 파싱해 출처
  신뢰도(confirmed/unknown)를 기록한다.
- 커밋마다 변경된 파일의 sha256 해시를 SQLite 기반 해시 체인(`.vibe-supervisor/ledger.db`)에
  추가한다. 중간 레코드를 고치면 그 이후 전체 체인이 깨져서 검출된다.
- 코드 본문은 저장하지 않는다 — 파일 해시만 남긴다.

아직 안 만든 것(다음 단계): IDE 확장 이벤트 캡처, 편집 패턴 분석, Semgrep
연동, 리포트 생성, 승인 플로우. 지원서의 4계층(출처추적·검사·감독·증빙) 중
"감독" 계층의 뼈대만 지금 있는 상태.

## 빠른 시작

```bash
npm install
npm run build

# 테스트할 다른 저장소로 이동해서
cd /path/to/some/repo
node /path/to/vibe-supervisor/dist/cli/index.js install

# 평소처럼 커밋
git commit -m "feat: 결제 모듈 추가

AI-Generated: claude-code, ratio=0.7"

# 원장 확인
node /path/to/vibe-supervisor/dist/cli/index.js log
node /path/to/vibe-supervisor/dist/cli/index.js verify
```
