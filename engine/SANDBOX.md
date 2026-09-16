# 샌드박스 — 신뢰할 수 없는 코드 격리 실행

생성된 익스플로잇이나 고객 코드 조각을 우리 호스트가 아니라 **격리된
환경**에서 실행한다. XBOW 가 익스플로잇을 컨테이너에서 검증하는 것과 같다.

## 두 층의 통제

### 1. 이그레스 통제 (항상, 프로세스 드라이버)
URL 스캔처럼 "요청만 보내는" 작업에 적용. `sandbox.js` 의 `guard()`.

```
허용 대상만 통과 · 사설대역/클라우드 메타데이터 차단 · 요청 상한 · 시크릿 마스킹
```

검증됨 (SANDBOX 이전 커밋). 스캐너가 제3자 공격 중계기가 되는 것을 막는다.

### 2. 격리 실행 (신뢰불가 코드, E2B 드라이버)
익스플로잇 스크립트를 microVM 에서 실행. `e2b-driver.js`.

| 항목 | 동작 |
|---|---|
| VM 생성 | `Sandbox.create({apiKey,timeoutMs})` |
| 스크립트 스테이징 | `sbx.files.write()` |
| 실행 | `sbx.commands.run()` → {stdout,stderr,exitCode} |
| **네트워크 격리** | `sbx.updateNetwork({allowInternet:false})` — 기본 차단 |
| **VM 폐기** | `sbx.kill()` — finally 로 항상 (XBOW 단명 워커) |
| 시크릿 마스킹 | stdout/stderr 를 Sandbox.redact 통과 |

드라이버 선택 순서: `e2b` > `docker` > 거부.
컨테이너 없이는 신뢰불가 코드 실행을 **거부**한다.

## 실제 E2B SDK 규약 대조

egress 프록시가 api.e2b.dev 를 차단하므로 라이브 호출은 못 했다. 대신
**실제 `e2b` SDK(npm v2.49.1)를 설치해 API 표면을 확인**하고 드라이버를
그에 맞췄다.

```
Sandbox static : list, create, connect, fork
Sandbox proto  : ..., updateNetwork, kill, files, commands, ...
```

드라이버가 이 규약을 올바르게 구동하는지 `e2b-mock.js`(동일 인터페이스)로
검증했다.

## 검증 결과 (목 샌드박스)

```
1. 정상 익스플로잇 실행     exitCode 0, stdout 마스킹됨 ✓
2. 네트워크 기본 차단       updateNetwork({allowInternet:false}) ✓
3. 실행 후 VM 폐기          net=false -> write -> run -> kill ✓
4. 크래시해도 VM 폐기       finally 로 kill ✓
```

시크릿 마스킹 실증: `sk_live_XXXX...` → `sk_l…[redacted]`

## fix/verify 연계

confirmed 취약점의 PoC 를 격리 VM 에서 재실행해, "관측"에 더해 "격리된
환경에서 재현된 익스플로잇"으로 뒷받침한다.

```
finding -> RED 회귀테스트 생성 -> PoC 스크립트 -> microVM 격리 실행 -> 증거(마스킹)
```

## 실제 인스턴스 검증 상태

라이브 E2B 검증은 egress 차단으로 못 했다. 실전에서는:

```bash
export E2B_API_KEY=<키>
npm i e2b
# driver:"e2b" 로 Sandbox 를 만들면 실제 microVM 사용
```

SDK 규약 대조 + 목 검증까지 완료했으므로, 라이브 연결은 API 키만 있으면
된다. 이 항목의 남은 10%는 라이브 스모크 테스트다.
