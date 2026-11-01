# Socket Inspector

Windows에서 Android 앱의 Frida 이벤트를 조회하고, 거래 코드·방향·문자열 조건에 따라 자동 치환하는 데스크톱 도구입니다. 현재 소스 기준 버전은 **3.2.4**입니다. 모든 앱의 통신을 자동 해석하는 범용 프록시는 아닙니다.

## 기능

- 패킷 목록, 원문·Hex·필드·변경 비교
- 본문 왼쪽 / 치환 규칙 오른쪽 배치
- 요청은 초록색, 응답은 파란색으로 표시
- 표에서 치환 규칙 추가·수정·삭제, 여러 거래 코드 일괄 등록
- Ctrl+1~5로 선택한 패킷에 색상 지정·해제, 세션에 보관
- 방향키 탐색, 편집 중 Alt+↑/↓, Ctrl+X 목록 비우기
- 세션 및 규칙 JSON 저장·불러오기

## 앱별 상태

| 프로필 | 상태 |
| --- | --- |
| 교보 `kr.com.wink` | 기존 앱별 Java 후크를 사용. 사용자 실기기에서 캡처 유지 확인 이력이 있습니다. |
| 신영 `com.shinyoung.mts` | 제공된 APK에 맞춘 어댑터 및 연결 진단. **실기기에서는 후크 없는 Frida 연결에도 앱 종료가 재현되어, 정상 사용 지원이 확인되지 않았습니다.** |

`src/compat-prelude.js`는 기존 교보 환경의 선택적 앱별 호환 설정입니다. 특정 라이브러리와 오프셋에 의존하며 다른 앱·버전으로 일반화할 수 없습니다. 신영에는 적용하지 않습니다.

## 실행

Windows / Python 3.12 환경 기준입니다.

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r src/requirements.txt
.venv\Scripts\python.exe src/app.py
```

Frida Python 클라이언트는 16.2.1로 고정되어 있습니다. 실제 단말 연결에는 호환되는 단말 Frida 서버가 필요합니다. 기기에는 `USB` 또는 접근 가능한 `host:port`를 입력합니다. 대상 앱을 선택한 뒤 연결하고, 다른 CLI 후크와 중복 연결하지 않습니다.

교보의 권장 연결은 앱 시작과 기존 호환 설정을 사용합니다. 신영은 휴대폰에서 직접 실행한 앱에 연결하며 기본값이 **연결만 검사**입니다. 진단 모드에서는 패킷이 수집되지 않습니다.

## 규칙

오른쪽 표의 선택 삭제는 남은 규칙을 검증한 뒤 고급 설정과 실제 적용 규칙에도 즉시 반영합니다. 마지막 규칙을 삭제하면 자동 치환이 OFF가 됩니다. 이미 OFF였던 상태는 유지합니다. 별도 고급 창에서는 저장/취소 방식을 유지합니다.

규칙 표에 방향·거래 코드/포함 조건·찾을 값·바꿀 값을 입력하고 추가한 뒤 **저장 후 자동 치환 켜기**를 누릅니다. 이미 처리된 패킷이 아닌 새로 발생하는 패킷부터 적용됩니다. `examples/rules.example.json`은 비활성 예시입니다.

포함 조건은 실제 패킷에 존재해야 합니다. 요청에만 있는 문자열을 응답 방향으로 설정하면 적용되지 않습니다. 규칙은 위에서부터 순차 적용하며, 조건 문자열 자체를 변경하는 규칙은 순서를 고려해야 합니다.

길이 변경을 허용해도 고정 폭 필드 위치나 별도 길이 헤더를 자동 추정하지 않습니다. 길이 정의는 실제 명세에 맞춰 설정해야 합니다. 메인 스레드 호출은 수동 대기시키지 않으며 신영 어댑터는 수동 대기를 지원하지 않습니다.

## 로컬 확인

다음 검사는 휴대폰에 연결하지 않습니다.

```powershell
Set-Location src
..\.venv\Scripts\python.exe -m unittest -v test_app
..\.venv\Scripts\python.exe test_direction_ui.py
..\.venv\Scripts\python.exe test_markers.py
..\.venv\Scripts\python.exe test_inline_rules.py
..\.venv\Scripts\python.exe test_profiles.py
..\.venv\Scripts\python.exe test_diagnostic.py
..\.venv\Scripts\python.exe test_rule_deletion.py
node test-shinyoung.cjs
```

`test_live_workflow.py`는 별도의 로컬 임시 프로세스에 실제 Frida로 연결하는 검사이며 Android 검증이 아닙니다. Node 검사는 Java 경계 모형으로 신영 어댑터를 검사합니다.

## Windows 실행 파일 빌드

```powershell
.venv\Scripts\python.exe -m pip install -r src/requirements-build.txt
.venv\Scripts\python.exe src/build.py
```

결과는 `build-output/SocketInspector/`에 생성됩니다. 실행 파일과 `_internal` 폴더를 함께 배포합니다. 런타임 라이브러리를 배포할 때에는 해당 의존성의 라이선스도 함께 확인해야 합니다.

이 저장소용 사본에는 소스·검사·비활성 예시만 포함했습니다. 실제 APK, 캡처·세션·사용자 규칙, 로그, 가상환경, 실행 파일은 포함하지 않습니다.
