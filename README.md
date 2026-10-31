# vibe-supervisor

AI 생성 코드에 대한 감독 계층. 탐지 정확도로 경쟁하지 않고, "이 코드는 누가
만들었고 누가 확인했는가"를 변조 불가능한 기록(Supervision Ledger)으로 남긴다.

## 현재 범위

**출처 추적 (1단계 — 커밋 트레일러 방식)**
- 커밋 메시지의 `AI-Generated: <tool>[, ratio=<0~1>]` 트레일러를 파싱해 출처
  신뢰도(confirmed/unknown)를 기록한다.
- 커밋마다 변경된 파일의 sha256 해시를 SQLite 기반 해시 체인(`.vibe-supervisor/ledger.db`)에
  추가한다. 중간 레코드를 고치면 그 이후 전체 체인이 깨져서 검출된다.
- 코드 본문은 저장하지 않는다 — 파일 해시만 남긴다.

**검사**
- `rulesets/ko-baseline-v1.yaml` 고정 룰셋(하드코딩 시크릿·SQL 문자열결합·eval/exec·약한 난수)으로
  Semgrep을 돌린다. `--config auto`(클라우드 레지스트리, 매번 바뀜) 대신 로컬 파일을 써서
  재현성을 지킨다 — 룰셋 파일 해시가 리포트에 그대로 찍힌다.
- SARIF의 OWASP 태그를 ISMS-P 영역명에 대략 매핑하되, 전부 `[확인 필요]`를 붙여
  심사 근거로 바로 인용하지 못하게 한다(현직 심사원 검증 전까지는 추정값).

**승인 플로우**
- `approve <id>`로 발견사항을 승인/예외 처리하고, 그 행위 자체를 원장에 기록한다.

**증빙**
- `report`로 실제 원장+발견사항 기반 리포트를 생성한다(기존엔 `demo.ts`의 가짜 데이터만 있었음).
  샘플 데이터와 실데이터를 리포트 상단 경고 문구로 명확히 구분한다.

**소급 재생성 방지 (외부 타임스탬프 앵커)**
- `anchor`로 원장 체인 끝 해시를 RFC3161 타임스탬프 기관(기본 FreeTSA.org)에 등록한다.
  해시 체인 자체는 변조는 막아도 "통째로 다시 만들기"는 못 막는다는, 지원서 Q4-2에서
  본인들이 직접 "가장 중요한 질문"으로 꼽은 구멍을 메우는 장치.
- `verify`가 체인 무결성뿐 아니라, 저장된 각 앵커 지점의 해시가 지금도 그대로인지까지
  같이 확인한다. 실제로 원장을 지우고 다른 내용으로 재생성하는 공격을 재현해봤더니
  "체인 무결성은 OK"가 뜨면서도(내부적으로는 일관된 새 체인이라) "앵커 불일치"로
  `verify`가 실패(exit 1)하는 걸 확인함 — 의도한 대로 동작.
- 리포트에도 앵커 상태가 별도 섹션으로 들어간다. 앵커가 없으면 "소급 재생성 여부를
  증명할 수 없음"이라고 솔직하게 표시한다.

아직 안 만든 것(다음 단계): IDE 확장 이벤트 캡처(조사해보니 Copilot은 외부 확장에 수락
이벤트를 공식 API로 안 열어줘서 완전한 구현이 어려움 — 지금 있는 커밋 트레일러 방식이
더 안정적인 1차 신호), 편집 패턴 분석, 앵커 자동 스케줄링(지금은 수동 `anchor` 호출).

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

# 방금 커밋에서 바뀐 파일만 검사 (전체 검사는 --all)
node /path/to/vibe-supervisor/dist/cli/index.js scan

# 발견사항 승인 (scan 출력에 찍히는 번호로)
node /path/to/vibe-supervisor/dist/cli/index.js approve 1 --note "환경변수로 이관 완료"

# 실제 원장+발견사항으로 리포트 생성
node /path/to/vibe-supervisor/dist/cli/index.js report

# 원장 끝 해시를 외부 TSA에 등록 (소급 재생성 방지)
node /path/to/vibe-supervisor/dist/cli/index.js anchor
```
