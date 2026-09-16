# Supabase / BaaS 어댑터

바이브코딩 사고의 실제 1위 원인 — RLS 오설정 (Supabase 노출의 83%).

## 입력

앱의 **공개 anon key** 와 프로젝트 URL 만 있으면 된다.
anon key 는 프론트엔드 번들에 이미 실려 나가는 값이라 비밀이 아니다.
service_role 키는 필요 없다.

```bash
node supabase-scan.js https://<project>.supabase.co <anon-key> [--write]
```

## 원리

RLS 정책은 레포에 파일로 없다 — Supabase 서버 상태다. 그래서 정책을 읽는
대신 **anon key 로 실제 요청을 보내 관측**한다. PostgREST 의 OpenAPI 루트로
테이블을 자동 발견하고, 각 테이블을 찔러 다섯 가지 실패 유형을 증명한다.

| 실패 유형 | 어떻게 검출 | 판정 |
|---|---|---|
| RLS off | anon GET 이 행을 반환 | confirmed |
| permissive `USING(true)` | anon GET 이 행을 반환 (위와 관측상 동일) | confirmed |
| partial coverage (쓰기 구멍) | anon POST 가 201 | confirmed (`--write`) |
| service_role 크라운주얼 | 잠겼으나 secret 컬럼 테이블 | needs_validation |
| secure (대조군) | anon 이 빈 배열 | passed |

민감 컬럼(email, stripe, key, card...)이 유출되면 심각도를 5로 올린다.

## 검증

목 PostgREST 서버(`experiment/supabase-mock`)에 다섯 유형을 심고 대조했다.

```
profiles      정답 rls_off       검출 rls_off_sensitive+write  ✓
posts         정답 permissive    검출 rls_off_sensitive        ✓
comments      정답 partial_write 검출 partial_write            ✓
api_keys      정답 secure        검출 없음(+크라운주얼 note)     ✓
private_msgs  정답 secure        검출 없음                      ✓

정확도 5/5, 오탐 0
```

## 개발 중 잡은 자체 결함

evidence 에 고객 PII(이메일, stripe_customer id)가 그대로 찍혔다.
"증거가 리포트로 새면 안 된다"는 원칙 위반이다. `Sandbox.redact` 가
`key:value` 형태만 잡고 이메일 값 형식은 못 잡았다. 이메일 정규식과
id 프리픽스(cus_/sk_/pk_...) 마스킹을 추가하고, 어댑터가 evidence 를
방출하는 시점에 redact 를 적용했다.

```
전: {"email":"alice@x.com","stripe_customer":"cus_alice"}
후: {"email":"al…@…[redacted]","stripe_customer":"cus_…[redacted]"}
```

## 한계

- Firebase/Convex/MongoDB Atlas 는 미지원 (PostgREST 규약만)
- `auth.uid()` 오용(같은 정책인데 비교 컬럼이 틀린 경우)은 로그인 계정이
  있어야 검출 가능. 현재는 anon 관점만
- 실제 Supabase 인스턴스로는 미검증 (목 서버로만 확인)
