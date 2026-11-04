# Socket Inspector

Windows에서 Android 앱의 Frida 이벤트와 PC ProvestK의 통신을 조회하는 데스크톱 도구입니다. 모바일 프로필은 거래 코드·방향·문자열 조건에 따른 자동 치환도 지원합니다. 현재 소스 기준 버전은 **3.3.0**입니다. 모든 앱의 통신을 자동 해석하는 범용 프록시는 아닙니다.

## PC ProvestK 조회 전용

1. 기존 뷰어의 연결을 해제하고 `PC-뷰어.cmd`를 실행합니다. PC 프로필로 바로 열립니다.
2. `SocketInspector.exe`로 직접 실행한 경우 상단 대상 앱에서 **교보 PC · ProvestK · 조회 전용**을 선택합니다.
3. ProvestK는 직접 실행합니다. **PC 프로세스 목록**에서 `provestkrun.exe · PID …`를 선택합니다. 본체 대신 실행기만 떠 있다면 실제 본체가 실행된 뒤 목록을 새로 조회합니다. `provestk.exe`도 선택할 수 있으나 통신을 담당하는 프로세스가 아닐 수 있습니다.
4. **연결 · 캡처 시작**을 누른 뒤 ProvestK에서 화면을 조회합니다.
5. 수집된 행을 선택해 Raw/Hex를 확인합니다. 요청은 초록, 응답은 파랑입니다. 방향키, Ctrl+1~5 색상, Ctrl+X 목록 비우기, 세션 저장도 사용할 수 있습니다.

PC는 로컬 Frida 장치에 연결하므로 휴대폰, adb, frida-server, 27042 주소 입력이 필요하지 않습니다. 실행 중인 프로그램에만 연결하며 자동 실행하지 않습니다. 권한 오류가 나고 HTS가 관리자 권한으로 실행 중이라면 뷰어도 같은 권한으로 실행해야 합니다.

수집 방식은 **소켓 + 평문 후보 / 소켓 원본 바이트 / 문자열 평문 후보** 중 선택합니다. 연결 후에도 바꿀 수 있습니다.

- **소켓 원본**: `send/recv/sendto/recvfrom/WSASend/WSARecv`의 바이트입니다. 송신은 실제 반환/완료 길이, 수신은 완료된 길이만 표시합니다. TCP 전문 경계는 아직 조립하지 않습니다. 여러 조각 또는 합쳐진 전문일 수 있고, 암호문·압축 데이터일 수 있습니다.
- **평문 후보**: 32비트 `LinkInfoMng.dll`의 `KSLink_KBEncryptData`, `KSLink_KBEncryptSeed128String` 문자열 변환 입력/출력입니다. 로컬 DLL의 정적 분석에 근거한 요청/응답 추정이며, 전체 전문·실제 송신 여부는 보장하지 않습니다. 별도 포인터 길이를 추측하지 않고 NUL로 끝난 최대 1 KiB 문자열만 읽습니다. 바이너리/다른 암호화 경로는 여기서 보이지 않습니다.
- 비동기 수신은 `WSAGetOverlappedResult`, IOCP `GetQueuedCompletionStatus/Ex`, WSA 완료 콜백을 관찰합니다. 다른 완료 처리 방식이나 이미 시작된 I/O는 누락될 수 있습니다.
- I/O당 앞 64 KiB, 초당 최대 100건/1 MiB 표시, 미완료 I/O 최대 256개로 제한합니다. 생략 수와 잘린 길이를 표시합니다. 전체 무손실 패킷 덤프가 아닙니다.
- **PC에서는 조회만 지원합니다.** 치환·중단·재전송은 설치하지 않으며 모바일용 사전 설정도 사용하지 않습니다.

연결 로그에 `Hook ready: PC`가 나온 뒤 새 화면을 조회하세요. 연결 종료가 발생하면 종료 시각과 마지막 로그를 확인하세요. 보호 기능 변경이나 종료 방지 패치는 포함하지 않았습니다.

검증: 별도 localhost 테스트 프로그램의 x86/x64 `send/recv`, WSABUF 분산 버퍼, 이벤트 기반 비동기 수신, IOCP 수신에서 정확한 원본 바이트와 중복 없는 수집을 확인했습니다. UI의 PID 선택, PC 조회 전용 강제, 모바일 복귀, 기존 규칙 저장/방향 색상/표시 기능도 검사했습니다. **실제 ProvestK 본체는 실행 중이 아니어서 HTS 연결·전문 캡처는 아직 미검증입니다.** 문자열 변환 검사는 경계 모형 검사이며 실제 HTS 평문 캡처 검증을 대신하지 않습니다.

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
| 교보 PC ProvestK | 조회 전용 수집기 추가. 로컬 x86/x64 테스트 통과, 실제 HTS 연결은 미검증. |
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

저장 버튼은 전용 저장 신호로 규칙과 ON 상태를 적용하고, 클릭/검증 실패/활성 규칙 개수를 표시합니다. 저장 후 재연결해도 ON 상태를 유지합니다. 사용 체크가 없는 규칙을 임의로 켜지는 않습니다.

새 규칙은 `mode: overwrite`인 원본 덮어쓰기가 기본입니다. 처음 일치하는 한 곳에 최대 찾기/바꾸기 폭만큼 덮고 짧은 값은 공백으로 채웁니다. 긴 값은 뒤 기존 바이트를 사용하며 전체 길이를 늘리지 않습니다. 경계를 넘으면 원본으로 진행합니다. 교보에서는 원래 byte 배열에 반영하며 덮어쓰기만 적용한 경우 길이 헤더 정의를 실행하지 않습니다. 기존 규칙은 자동 변경하지 않으며, 기존 규칙 전환 후 저장하거나 방식 열을 사용하세요. `mode` 없는 파일은 기존 일반 치환으로 읽습니다.

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
..\.venv\Scripts\python.exe test_save_button.py
node test-shinyoung.cjs
node test-overwrite.cjs
node test-windows-strings.cjs
..\.venv\Scripts\python.exe test_windows.py
..\.venv\Scripts\python.exe test_windows_native.py
..\.venv\Scripts\python.exe test_overwrite.py
```

`test_live_workflow.py`는 별도의 로컬 임시 프로세스에 실제 Frida로 연결하는 검사이며 Android 검증이 아닙니다. Node 검사는 Java 경계 모형으로 신영 어댑터를 검사합니다.

## Windows 실행 파일 빌드

```powershell
.venv\Scripts\python.exe -m pip install -r src/requirements-build.txt
.venv\Scripts\python.exe src/build.py
```

결과는 `build-output/SocketInspector/`에 생성됩니다. 실행 파일과 `_internal` 폴더를 함께 배포합니다. 런타임 라이브러리를 배포할 때에는 해당 의존성의 라이선스도 함께 확인해야 합니다.

이 저장소용 사본에는 소스·검사·비활성 예시만 포함했습니다. 실제 APK, 캡처·세션·사용자 규칙, 로그, 가상환경, 실행 파일은 포함하지 않습니다.

`test_windows_native.py`는 Windows .NET Framework C# 컴파일러로 임시 x86/x64 테스트 프로세스를 만들고 localhost echo 통신만 검사합니다. 실제 HTS에 연결하지 않으며 임시 파일은 검사 후 삭제합니다.
