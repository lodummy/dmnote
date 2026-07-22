# DM NOTE 악성코드 여부 분석

누가 바이러스 쳐 있다고 하고 그걸 나로 생각하길래 직접 두세시간정도 분석해봤습니다

---

## TL;DR

악성코드·키로거·무단 개인정보 수집 징후는 발견되지 않았다. 확인된 모든 파일·레지스트리·네트워크 동작은 Tauri 프레임워크와 WebView2(Chromium) 엔진의 정상적인 초기화/캐싱/정책 조회 절차로 설명. 프로세스 인젝션, 영속성, 지갑 타겟팅, C2 통신 관련 코드는 전무.

---

## 1. 분석 배경 및 대상

다운로드한 `DM.NOTE.exe` 실행 파일에 대해 바이러스, 키로거, 또는 불필요한 개인정보 수집 등 악성 행위 여부를 확인하기 위해 정적 분석과 동적 분석을 순차적으로 진행하였다.

| 항목 | 내용 |
|---|---|
| 파일명 | `DM.NOTE.exe` |
| 경로 | `C:\Users\Administrator\Downloads\DM.NOTE.exe` |
| 관련 프로세스 | `DmNoteRawInput`(입력 캡처 데몬), `DM Note Overlay`(오버레이/OBS 렌더링) |
| 빌드 스택 | Rust + Tauri 프레임워크, WebView2(Microsoft Edge 엔진) 기반 UI |
| 추정 정체 | 키보드 입력 시각화·사운드 재생·OBS 오버레이용 데스크톱 프로그램 (리듬게이머/스트리머 대상) |
| 앱 식별자 | `com.dmnote.desktop` |
| 창 제목 | `"DM Note"` (설정 창: `"DM Note - Settings"`) |
| 사용 도구 | IDA, x64dbg |

---

## 2. 정적 분석 (IDA)

### 2.1 앱 정체 확인

Import 테이블 및 문자열 분석 결과, 이 프로그램은 **Rust로 작성되고 Tauri 프레임워크로 패키징된 정상적인 데스크톱 애플리케이션**으로 확인되었다.

Tauri IPC 커맨드 목록에서 아래와 같은 명령어가 발견되었으며, 이는 키 입력에 맞춰 사운드/애니메이션을 재생하고 OBS 오버레이를 제공하는 프로그램임을 나타낸다:
```
key_sound_*, gridSettings, keySoundOutputBackend, soundLibrary,
counter_animation_*, obs_status
```

### 2.2 키 입력 캡처 로직 분석

`RegisterRawInputDevices` 및 HID API(`HidP_GetValueCaps` 등)를 사용하는 raw input 데몬 함수(`sub_14014F7B1`)를 직접 디컴파일하여 확인.

- 키 코드를 레이블 문자열(예: `"RIGHT ALT"`)로 변환한 뒤, **사운드 재생 및 오버레이 표시용 내부 함수만 호출**.
- **파일에 입력 내용을 기록하거나 네트워크로 전송하는 코드는 발견되지 않음.**

### 2.3 네트워크 관련 문자열 및 API 분석

| 문자열/구성요소 | 판단 |
|---|---|
| `127.0.0.1` 로컬 HTTP 서버 (`/obs/index.html?port=&token=`) | OBS 브라우저 소스 연동용, 외부로 나가지 않는 로컬 전용 통신 |
| `github.com/.../releases/download/`, `dm-note-auto-updater` | 정상적인 GitHub 기반 자동 업데이트 로직 |
| `reqwest`, `hyper`, `rustls` | Tauri 앱에 흔히 포함되는 표준 Rust HTTP/TLS 라이브러리 |

### 2.4 의심 패턴 검색 (1차)

아래 항목들을 정규식으로 전수 검색하였으나 **어떠한 항목도 발견되지 않았다**:
```
http, .php, password, keylog, clipboard, discord, webhook, telegram,
AppData, browser, cookie, wallet, token, api_key, .onion,
discord.com/api/webhooks, pastebin, ngrok, grabber, stealer, credential,
autofill, Login Data, cookies.sqlite, Telegram, smtp, ftp://, api.telegram
```
→ 브라우저 저장 자격증명 경로, Discord 웹훅, 텔레그램 봇 토큰, 페이스트빈/ngrok, C2로 의심되는 하드코딩 IP·도메인 등 전무.

### 2.5 connect / getaddrinfo 호출 경로 추적

- `connect()` 함수의 호출부(`sub_1402DAADF` → `sub_1402D9D2A`)는 **Tokio/mio 비동기 런타임 내부의 범용 TCP 연결 상태 머신**으로, 특정 도메인에 고정되어 있지 않음.
- `getaddrinfo()` 호출부(`sub_140520780`) 역시 임의의 문자열을 인자로 받는 **범용 `ToSocketAddrs` 변환 함수**로, 실제 조회 대상은 런타임 시점의 호출자가 결정하는 구조.
- 참고: Rust 표준 라이브러리는 `127.0.0.1`과 같은 리터럴 IP 문자열의 경우 `getaddrinfo` 호출 자체를 생략하는 경우가 있어, 로컬 서버 바인딩만으로는 이 경로가 실행되지 않을 수 있음.

### 2.6 프로세스 인젝션 API 존재 여부 (추가 검증)

Import 테이블에서 아래 API들을 전수 조회 — **전부 0건, import 자체가 없음**:
```
VirtualAllocEx, WriteProcessMemory, CreateRemoteThread,
SetWindowsHookEx, NtUnmapViewOfSection, QueueUserAPC
```
→ 다른 프로세스에 코드를 주입하는 것이 **구조적으로 불가능**.

### 2.7 영속성 / 지갑 타겟팅 검색 (추가 검증)

```
CurrentVersion\Run, schtasks, wallet.dat, mnemonic, seed phrase,
metamask, keystore, BitLocker, shadow copy, vssadmin
```
→ 전부 0건.

### 2.8 하드코딩 외부 도메인 전수조사 (추가 검증)

정규식 `[a-z0-9-]+\.(com|net|io|dev|xyz|top|ru|cn|info|biz|cc|to|gg)/` 로 전체 스캔한 결과, 발견된 것은 전부 무해함:

- `github.com` — Tauri 프레임워크 자체 소스의 이슈 링크(`tauri-apps/wry`, `tauri-apps/muda`), 업데이트 다운로드
- `developer.microsoft.com` — WebView2 런타임 설치 안내 페이지
- 나머지는 영단어 뒤섞임 코퍼스 데이터에서 우연히 도메인 패턴처럼 매치된 것 (실제 URL 아님)

---

## 3. 동적 분석 (x64dbg)

정적 분석만으로는 실제 런타임 동작을 100% 보장할 수 없으므로, x64dbg를 프로세스에 attach하여 핵심 API 호출 지점에 브레이크포인트를 걸고 실제 동작을 관찰하였다.

### 3.1 브레이크포인트 설정 및 관찰 결과

| API | 목적 | 관찰 결과 |
|---|---|---|
| `getaddrinfo` (ws2_32) | DNS 조회 도메인 확인 | 히트 없음 |
| `connect` (ws2_32) | 실제 접속 IP/포트 확인 | 히트 없음 |
| `send` / `WSASend` (ws2_32) | 전송 데이터 확인 | 히트 없음 |
| `CreateFileW` (kernel32) | 파일 열기/생성 경로 확인 | 자기 자신 경로, WebView2 런타임 후보 경로만 확인 (정상) |
| `WriteFile` (kernel32) | 파일 쓰기 내용 확인 | 히트 1회 — §3.2 참고 |
| `RegOpenKeyExW` (advapi32) | 레지스트리 접근 범위 확인 | HKCU/HKLM WebView2 정책 키, 읽기 전용(`KEY_READ`) |

### 3.2 WriteFile 호출 상세 분석

동적 분석 중 유일하게 관측된 `WriteFile` 호출(`hFile` 핸들 대상 184바이트 기록)에 대해 콜스택 리턴 주소를 모듈 메모리 맵과 대조:

- 호출 지점이 **`dm.note.exe` 자체 코드가 아닌 `embeddedbrowserwebview.dll`**(Microsoft WebView2 임베디드 브라우저 엔진) 내부인 것으로 확인.
- 기록된 데이터 또한 사람이 읽을 수 있는 텍스트가 아닌 이진 구조체 형태로, 크로미움 기반 엔진이 통상적으로 기록하는 캐시/세션 데이터의 특징과 일치.
- **결론: DM Note 자체의 로깅 코드가 아니라 Microsoft가 제공하는 WebView2 엔진의 표준 캐시 기록 동작.**

### 3.3 CreateFileW 호출 상세 (WebView2 탐색 루틴)

아래 후보 경로들을 순회하며 존재 여부를 확인하는 정상 초기화 패턴을 확인:
```
C:\Users\Administrator\Downloads\DM.NOTE.exe          (자기 자신, 속성 조회 — 업데이터 버전 체크로 추정)
C:\Users\Administrator\Downloads\webview2-fixed-runtime
C:\Users\Administrator\Downloads\WebView2FixedRuntime
C:\Users\Administrator\Downloads\resources\webview2-fixed-runtime
```
`dwDesiredAccess = 0`(속성 조회 전용), `dwShareMode = 7`(READ|WRITE|DELETE 공유) — 파일을 잠그지 않고 존재만 확인하는 전형적인 패턴.

### 3.4 RegOpenKeyExW 호출 상세

`HKEY_CURRENT_USER` → `HKEY_LOCAL_MACHINE` 순으로 `Software\Policies\Microsoft\Edge\WebView2...` 조회. WebView2의 표준 그룹 정책 우선순위 체크(엔터프라이즈 정책 오버라이드 확인용), 읽기 전용.

### 3.5 네트워크 API 미관측에 대한 검토 (재시도 포함)

- `connect`, `send`, `WSASend`, `getaddrinfo`에는 동적 분석 전 구간(**앱 완전 재시작 후 `init`으로 프로세스 생성 시점부터 attach하여 재시도 포함**, 설정 조작, OBS 연동 토글 포함)에서 **단 한 차례도 히트가 발생하지 않았다.**
- 정적 분석에서 확인한 바와 같이 이 API들의 호출부가 조건부(예: 업데이트 체크 트리거, 스로틀링 로직) 실행 구조이거나, 로컬 IP 리터럴에 대해서는 애초에 `getaddrinfo`가 생략되는 Rust 표준 라이브러리의 특성상 자연스러운 결과로 판단된다.
- 코드 경로 자체가 범용 라이브러리 함수이고 특정 도메인에 하드코딩되어 있지 않다는 점(§2.5)에서, 의도적 은폐 정황으로 보기는 어렵다.

### 3.6 DmNoteRawInput 별도 프로세스 분석

raw input 캡처를 전담하는 별도 프로세스. 재시작 후 attach하여 관찰한 결과, 살아있는 동안 `connect`/`send`/`WSASend`/`getaddrinfo`/`WriteFile`이 **전혀 호출되지 않았다.** WebView2 경로 탐색과 정책 조회만 수행 후 정상 종료(`exit code 0`).

---

## 4. x64dbg 문자열(Strings) 재검토

x64dbg의 전체 프로세스 메모리 문자열 스캔에서 자극적으로 보일 수 있는 단어들이 다수 검출되었으나, 소속 모듈과 문맥을 분석한 결과 **전부 무해함**으로 판정되었다.

### 4.1 "server" 키워드 검색 결과

| 카테고리 | 예시 | 실제 소속/의미 |
|---|---|---|
| Windows COM/RPC 인프라 | `CServerContextActivator`, `InprocServer32`, `RpcServerRegisterIf2` | `combase.dll`/`advapi32.dll` 자체 문자열 — 모든 윈도우 프로그램에 존재 |
| Rust 오픈소스 크레이트 | rustls/http/hyper/tungstenite 에러명 나열 | crates.io 공개 라이브러리 소스 (`rustls-0.23.36`, `http-1.4.0` 등) |
| WebView2/Chromium 내부 | `ICoreWebView2ServerCertificateErrorDetectedEventHandler` | 브라우저 엔진 이벤트 핸들러 이름 |
| Terminal Server 레지스트리 경로 | `...CurrentVersion\Terminal Server` | OS 라이브러리가 RDP 세션 여부 등을 체크할 때 쓰는 표준 경로 |
| **DM Note 자체 코드** | `--proxy-server=http://`, `--proxy-server=socks5://` | `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS`. 값이 비어있어 사용자가 프록시를 설정했을 때만 채워지는 조건부 로직으로 추정. 악성 아님 |

### 4.2 "VirtualAlloc" / "CreateRemoteThread" 등 인젝션 연상 키워드 검색 결과

| 문자열 | 실제 소속/의미 |
|---|---|
| `"VirtualAlloc failed"`, `"WER/CrashAPI:... VirtualAlloc failed"` | **Windows Error Reporting**(크래시 리포팅) 표준 문자열, `kernelbase.dll` 소속. 모든 윈도우 프로그램에 존재 |
| `"CreateRemoteThreadEx"`, `"CsrCreateRemoteThread"` | `ntdll.dll`이 **자기 자신의 API를 구현**하며 갖고 있는 심볼 문자열. DM Note가 호출하는 게 아님 — §2.6에서 import 자체가 없음을 이미 확인 |
| `"Page.captureScreenshot"` | **Chrome DevTools Protocol** 표준 명령어. WebView2/Chromium 엔진에 기본 내장. `--remote-debugging-port` 플래그 없이는 도달 불가 (커맨드라인 인자에 해당 플래그 없음 확인됨) |
| `L"screenshot"` | 작업표시줄 미리보기/Aero Peek 등 표준 윈도우 셸 기능 관련 DLL 소속으로 추정 |

**핵심 원칙:** 문자열이 프로세스 메모리 어딘가에 "존재"하는 것과, `dm.note.exe`의 **import 테이블에 있고 + 실제 코드에서 호출(xref)되는 것**은 전혀 다른 문제다. 후자 기준으로 검증했을 때 위험 API는 전무하다.

---

## 5. 종합 결론

| 검증 항목 | 결과 |
|---|---|
| 의심 문자열(C2, 웹훅, 자격증명 경로 등) | ❌ 없음 |
| 백도어성 Import API | ❌ 없음 (표준 Tauri/Rust 스택) |
| 프로세스 인젝션 API | ❌ 없음 (VirtualAllocEx 등 import 자체 부재) |
| 영속성/지갑 타겟팅 문자열 | ❌ 없음 |
| 하드코딩 외부 도메인 | ❌ 없음 (github.com, MS 공식 사이트뿐) |
| 파일 쓰기(WriteFile) | ✅ WebView2 엔진의 정상 캐시 기록으로 확인 |
| 파일 열기(CreateFileW) | ✅ 자기 자신 + WebView2 런타임 경로 조회뿐 |
| 레지스트리 접근 | ✅ WebView2 정책 조회, 읽기 전용 |
| 키 입력 캡처 로직 | ✅ 사운드/오버레이 표시용 내부 함수만 호출 |
| 실사용 중 외부 네트워크 연결 | ✅ 관찰된 적 없음 (재시작 재시도 포함) |
| Strings 탭 재검토(server/VirtualAlloc/CreateRemoteThread 등) | ✅ 전부 OS/프레임워크 표준 문자열로 확인, DM Note 자체 호출 없음 |

> **결론: 정적 분석과 동적 분석 전 과정에서 키로깅, 자격증명 탈취, C2 통신, 프로세스 인젝션, 무단 개인정보 수집 등 악성 행위를 시사하는 증거는 발견되지 않았다. 확인된 모든 파일/레지스트리/네트워크 관련 동작은 Tauri 프레임워크와 WebView2 엔진의 정상적인 초기화·캐싱·정책 조회 절차로 설명 가능하다.**

---

## 6. 분석의 한계

- 동적 분석은 실제로 실행/트리거해 본 코드 경로에 대해서만 검증이 가능하며, 스로틀링되어 드물게 실행되는 로직(예: N시간 단위 업데이트 체크)은 관측하지 못했을 가능성이 있다.
- 난독화되었거나 조건부로만 활성화되는 코드 경로, 원격 설정에 따라 동작이 바뀌는 로직 등은 정적/동적 분석만으로 완전히 배제하기 어렵다.
- 본 분석은 특정 시점의 특정 빌드(다운로드된 `DM.NOTE.exe`)를 대상으로 하였으며, 향후 업데이트된 버전에는 적용되지 않는다.

---

## 7. 결론

놀라울정도로 수상한코드 하나 발견되지않아 재미가 없었어요 
