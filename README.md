# vibe-supervisor

AI 생성 코드에 대한 감독 계층. 탐지 정확도로 경쟁하지 않고, "이 코드는 누가
만들었고 누가 확인했는가"를 변조 불가능한 기록(Supervision Ledger)으로 남긴다.

## 현재 범위

**출처 추적 (1단계 — 커밋 트레일러 방식)**
- 출처 신뢰도는 3단계로 기록한다.
  - 확정(confirmed): 개발자가 `AI-Generated: <tool>[, ratio=<0~1>]` 트레일러로 선언. ratio도 원장에 남는다.
  - 추정(estimated): AI 도구가 붙이는 공동작성자 트레일러(`Co-Authored-By: Claude/Copilot/Cursor…`).
  - 미상(unknown): 신호 없음. "AI 미사용"이 아니라 "모름"으로 표기한다.
- 커밋마다 변경된 파일의 sha256 해시를 SQLite 기반 해시 체인(`.vibe-supervisor/ledger.db`)에
  추가한다. 중간 레코드를 고치면 그 이후 전체 체인이 깨져서 검출된다.
- 코드 본문은 저장하지 않는다 — 파일 해시만 남긴다.

**커밋 서명 — actor 신뢰도 보강**
- `actor`(git `user.email`)는 누구나 아무 값이나 설정할 수 있어 신원 근거로 약하다.
  post-commit 훅이 커밋마다 `git log --format=%G?` 기반으로 GPG/SSH 서명 여부·서명자를
  같이 기록해, "이메일이 이렇다고 주장함"과 "이 키 소유자가 실제로 서명함"을 구분한다.
- 서명이 없는 게 기본값이라 대부분 `none`으로 찍히는 게 정상이다 — 없는 걸 있는 척
  표기하지 않는다. 리포트에 "N/M건 서명됨" 비율로 들어간다.

**승인 행위 서명 (SSH)**
- `approve`가 승인 내용(발견사항·결정·사유·규칙·파일·라인·처리자·커밋)을 `ssh-keygen -Y sign`으로
  서명해 원장 레코드에 같이 넣는다. 키는 `--sign-key <경로>`, 없으면 git 커밋 서명 설정
  (`gpg.format=ssh` + `user.signingkey`)을 그대로 따른다. 키가 없으면 지금처럼 서명 없이 기록한다.
- 서명하려다 실패하면(키 경로 오류, agent에 키 없음) 승인 자체를 기록하지 않는다 — 조용히
  미서명으로 남기면 "서명된 줄 알았다"가 된다.
- namespace를 `vibe-supervisor-approval`로 고정해, 같은 키로 만든 git 커밋 서명을 승인 서명으로
  끼워 넣을 수 없다.
- `verify`의 [5/5] 단계가 서명을 다시 검증한다. `--allowed-signers <파일>`(또는 git의
  `gpg.ssh.allowedSignersFile`)을 주면 "그 키가 처리자 이메일로 등록된 본인 키인가"까지 확인해,
  남의 키로 본인 이메일을 주장한 승인은 실패(exit 1)로 걸린다. 서명 없는 승인은 실패가 아니라
  비율로 리포트에 표기된다.
- 원장을 통째로 다시 계산해 사유를 바꾸는 공격도, 서명된 승인이라면 서명 불일치로 걸린다
  (앵커가 없어도).

**검사**
- 커밋 시점에 바뀐 파일만 자동으로 증분 검사한다(post-commit 훅). 로컬 `semgrep`이 없으면
  버전을 고정한 Docker 이미지(`semgrep/semgrep:1.95.0`)로 대신 돌린다. `VS_SKIP_SCAN=1`이면 건너뛴다.
- `rulesets/ko-baseline-v1.yaml` 고정 룰셋(하드코딩 시크릿·SQL 문자열결합·eval/exec·약한 난수)으로
  Semgrep을 돌린다. `--config auto`(클라우드 레지스트리, 매번 바뀜) 대신 로컬 파일을 써서
  재현성을 지킨다 — 룰셋 파일 해시가 리포트에 그대로 찍힌다.
- `scan --all`(전체 검사)도 실제 스캔 자체는 semgrep의 gitignore 인식 전체 순회에
  맡기지만, "어떤 파일을 봤는지"는 `git ls-files`로 따로 계산해 원장에 남긴다 —
  이게 없으면 전체 검사는 재검사 근거로 못 쓰인다(아래 "조치 완료" 판정 참고).
  고친 뒤 `scan --all`로 다시 돌려 "조치 완료(재검사 확인: 커밋 …)"가 찍히는 걸
  실제로 확인함.
- SARIF의 OWASP 태그를 ISMS-P 영역명에 대략 매핑하되, 전부 `[확인 필요]`를 붙여
  심사 근거로 바로 인용하지 못하게 한다(현직 심사원 검증 전까지는 추정값).

**외부 도구 SARIF 가져오기**
- `import-sarif <파일> [--tool 이름]`로 semgrep이 아닌 다른 SAST/DAST 도구(조직에
  이미 있는 상용 스캐너 등)의 SARIF 2.1.0 결과도 같은 findings.db·원장 경로로
  편입시킬 수 있다. 재현성 근거는 우리 룰셋 해시 대신 "가져온 SARIF 파일 자체의
  해시"를 쓴다 — 그 도구의 스캔 로직까지 우리가 고정·검증했다고 주장하지 않는다.
- 어떤 파일을 스캔했는지는 통제할 수 없으므로 fileHashes를 비워 둔다 — 그래서
  재검사 근거(조치 완료 판정)로는 안 쓰인다. 직접 `approve`로 처리해야 한다.
- 리포트는 출처가 섞이면(semgrep + 외부 도구) "탐지 도구" 칸과 5장에 각 출처를
  따로 나열한다 — "이 룰셋 하나로 전부 재현 가능"이라는 말이 거짓이 되지 않게.
- 실제 가짜 SARIF 파일(FakeSAST 도구, XSS 1건)을 semgrep 발견사항과 함께 가져와
  리포트(마크다운·HTML 둘 다)가 두 출처를 올바르게 구분해 보여주는 걸 확인했다.

**승인 플로우**
- `approve <id>`로 발견사항을 **조치 완료(`--fixed`) / 승인(위험 수용) / 예외(`--exception`)** 중 하나로 처리하고,
  그 행위 자체를 원장에 기록한다. 조치 완료는 조치 내용, 예외는 사유(`--note`)가 필수.
- "고쳤다"와 "그대로 두기로 했다"를 구분한다. 조치 완료 항목은 원장의 재검사 기록(같은 파일을 다시 검사했는데
  같은 규칙이 더는 안 나옴)이 있으면 리포트에 "재검사 확인: 커밋 …"으로, 없으면 "재검사 근거 없음"으로 표기한다.
  커밋 시점 재검사에서 기존 미승인 항목이 사라지면 훅이 알려주지만, 상태를 자동으로 닫지는 않는다(판단은 사람이 기록).
- 승인 대상(규칙·파일·라인)·결정·사유가 원장 레코드의 해시에 포함된다. 탐지 기록도 마찬가지로
  "어떤 발견사항이 몇 번으로 저장됐는지"를 체인에 고정한다. 그래서 `findings.db`를 직접 고치면
  (사유 수정, 원장 없이 승인, 항목 삭제·추가) `verify`의 "발견사항·승인 대조"에서 걸린다.
  기존 원장(이 기능 이전 레코드)은 그대로 검증되고, 대조 근거가 없는 구버전 발견사항은 따로 센다.

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
- `anchor`는 TSA 응답의 nonce·messageImprint·서명을 받는 즉시 검증하고, 통과한 토큰만 저장한다.
- `verify`는 저장된 토큰의 TSA 서명을 다시 검증하고, 서명된 해시를 anchors.db의 값이 아니라 **지금 원장의
  해당 레코드 해시**와 대조한다. 원장을 재계산하면서 anchors.db의 해시까지 맞춰 고치는 공격도 걸린다.
  `--tsa-ca <루트인증서.pem>`을 주면 서명자 인증서 체인까지 확인한다(FreeTSA: https://freetsa.org/files/cacert.pem).
- 리포트에도 앵커 상태가 별도 섹션으로 들어간다. 앵커가 없으면 "소급 재생성 여부를
  증명할 수 없음"이라고 솔직하게 표시한다.

**기록 완전성 (빠진 커밋 찾기)**
- 해시 체인·앵커는 "있는 기록을 고치지 않았다"만 보장한다. 훅을 거치지 않은 커밋은 애초에
  기록이 없으므로, `verify`의 4번째 검사가 git 이력과 원장을 대조해 **기록이 없는 커밋**을 찾는다.
- 직접 확인한 훅 동작(git 2.x): `commit --no-verify`·`--amend`·cherry-pick·rebase·revert는
  post-commit 훅이 실행된다. 반면 `merge --no-ff`의 병합 커밋, `-c core.hooksPath=…`로 훅을
  바꾼 커밋, 훅이 설치되지 않은 곳에서 만든 커밋은 기록이 남지 않는다.
- 판정: 기록 없는 **일반 커밋 → 실패(exit 1)**. 병합 커밋(원래 훅이 안 도는 동작)·보안 검사 기록이
  없는 커밋(`VS_SKIP_SCAN=1`, semgrep 미설치 등)·원장에만 있고 이력엔 없는 커밋(amend·rebase)은
  실패가 아닌 경고로 따로 표시한다.
- 기준점은 "현재 이력 중 원장에 기록된 가장 오래된 커밋" — 도구 도입 전 커밋은 누락으로 세지
  않는다. `verify --since <커밋>` / `report --since <커밋>`으로 직접 지정할 수 있다.
- 한계: 원장은 저장소 사본마다 따로 쌓이므로, 다른 사람이 만든 커밋을 pull하면 이 사본에선
  누락으로 보인다(팀 단위 원장 통합·서버 측 검사는 다음 단계).

**리포트 구성**: 요약 → ISMS-P 2.8.1~2.8.6 대응 범위(커버/부분/대상 아님) → 발견사항별 탐지·처리 시각과
출처 → 예외 내역 → 출처 분포 → 재현성 → 무결성 설명·앵커 검증 결과·기록 완전성·알려진 한계 → 원장 부록.

**시연·미팅 자료**
- `bash demo/run-demo.sh`: 임시 Java/Spring 저장소에서 커밋 → 자동 검사 → 수정·승인·예외 → 앵커 →
  리포트 → 변조 3종(사유 수정 / 원장 없이 승인 / 원장 재계산+앵커 해시 수정)을 시연하고 전부 검출되는 걸 보여준다.
  `DEMO_OFFLINE=1`(TSA 생략), `DEMO_PAUSE=1`(단계별 정지), `DEMO_DIR=…`(작업 폴더) 옵션.
- `docs/meeting-guide.md`: 보안담당자·심사원 미팅 질문지, 시연 순서, 남길 것, 예상 반론.

**테스트**: `npm test` — 원장 payload 변조, 구버전 원장 호환, 발견사항 DB 변조·삭제·삽입, 트레일러 판정,
기록 완전성(누락·병합·이력 변경·검사 누락, 실제 git 저장소 대조), 승인 서명.

**변조 검출률 실측 (사업계획서 [표 8])**: `test/tamper-property.test.ts`가 fast-check로 무작위
레코드·컬럼·값을 골라 SQLite 파일을 직접 고친다. 기본 200회, `VS_TAMPER_RUNS=1000 npm test`로
늘릴 수 있다. 2026-11-07 기준 원장 컬럼 변조·발견사항 필드 변조 각각 1000회 × 3번 모두 검출(100%).
이 측정에서 "처리 전 항목에 처리자·사유만 끼워 넣기"가 빠져나가는 걸 찾아 대조 검증에 추가했다.
검출 범위 밖인 것도 테스트에 고정해 뒀다:
- 원장 **끝** 레코드 삭제는 해시 체인만으로는 못 잡는다 — 외부 앵커(`anchor`)가 있어야 잡힌다.
- 발견사항의 심각도·메시지·조항 매핑은 원장에 고정돼 있지 않아 DB를 고쳐도 대조에서 안 걸린다.

**앵커 자동 스케줄링**
- 기본은 off — 매 커밋마다 외부 TSA 네트워크 호출이 생기는 걸 원치 않을 수 있어서,
  설치 직후엔 지금까지처럼 수동 `anchor`만 동작한다.
- `config --auto-anchor on`으로 켜면, post-commit 훅이 매 커밋 뒤 "마지막 앵커 이후
  커밋 N건 경과" 또는 "마지막 앵커 이후 N시간 경과" 중 하나라도 차면 알아서 TSA에
  타임스탬프를 요청해 저장한다. 두 기준 다 기본 `.vibe-supervisor/config.json`에서
  조정 가능(`everyNCommits`, `maxAgeHours`).
- 네트워크가 느리거나 끊겨 있어도 커밋 자체는 절대 막지 않는다 — 요청에 타임아웃을
  걸고, 실패하면 경고만 찍고 조건은 그대로 남겨 다음 커밋에서 재시도한다.
- 버그 하나 잡음: 앵커가 한 번도 없을 때 "마지막 앵커 이후 경과 시간"을 `Infinity`로
  두면 시간 조건이 커밋 수와 무관하게 항상 참이 돼서 everyNCommits 설정을 무시하고
  첫 커밋부터 바로 앵커링되는 문제가 있었다 — 재현 테스트로 확인 후, 앵커가 없을 땐
  원장의 첫 기록 시각을 기준 시각으로 쓰도록 고쳤다.

아직 안 만든 것(다음 단계): IDE 확장 이벤트 캡처(조사해보니 Copilot은 외부 확장에 수락
이벤트를 공식 API로 안 열어줘서 완전한 구현이 어려움 — 지금 있는 커밋 트레일러 방식이
더 안정적인 1차 신호), 편집 패턴 분석,
승인자 신원의 SSO 연동(지금은 SSH 서명 + 허용 서명자 목록까지 — 그 목록의 관리 책임은 조직에 있다),
발견사항의 심각도·메시지까지 원장에 고정하기,
병합 커밋 기록(post-merge 훅), 팀 단위 원장 통합과 서버/CI 측 완전성 검사.

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

# 다른 SAST/DAST 도구의 SARIF 결과도 같이 편입 (선택)
node /path/to/vibe-supervisor/dist/cli/index.js import-sarif other-tool-results.sarif --tool "SomeScanner"

# 발견사항 승인 (scan 출력에 찍히는 번호로)
node /path/to/vibe-supervisor/dist/cli/index.js approve 1 --fixed --note "환경변수로 이관"
node /path/to/vibe-supervisor/dist/cli/index.js approve 2 --exception --note "내부 배치 전용 — 다음 분기 재검토"

# 실제 원장+발견사항으로 리포트 생성
node /path/to/vibe-supervisor/dist/cli/index.js report

# 인쇄·제출용 HTML (브라우저에서 열고 '인쇄 / PDF로 저장' → PDF. 발견사항 표는 가로 페이지)
node /path/to/vibe-supervisor/dist/cli/index.js report -o report.html

# 원장 끝 해시를 외부 TSA에 등록 (소급 재생성 방지, 수동)
node /path/to/vibe-supervisor/dist/cli/index.js anchor

# 매 커밋 뒤 조건 충족 시 자동으로 anchor까지 실행 (기본 off)
node /path/to/vibe-supervisor/dist/cli/index.js config --auto-anchor on --every-n-commits 10 --max-age-hours 24
```
