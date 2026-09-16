# 프레임워크 지원 + 실전 검증 하니스

## Next.js 라우트 발견 (2번)

Next 는 바이브코딩의 지배적 스택이다 (Lovable, v0, Bolt 전부 Next 출력).
라우트가 파일 시스템 기반이라 Express 정규식으로는 하나도 못 잡는다.
`discover-next.js` 가 파일 위치에서 URL 을 유도한다.

| 대상 | 예 | 유도 결과 |
|---|---|---|
| App Router 핸들러 | `app/api/users/[id]/route.ts` | `GET/DELETE /api/users/:id` |
| 중첩 동적 세그먼트 | `app/api/posts/[id]/comments/[cid]/route.ts` | `/api/posts/:id/comments/:cid` |
| Route group | `app/(marketing)/blog/route.ts` | `/blog` (그룹 무시) |
| Catch-all | `app/api/files/[...path]/route.ts` | `/api/files/*` |
| Page | `app/dashboard/page.tsx` | `/dashboard` |
| Pages API | `pages/api/webhook.ts` | `/api/webhook` |
| Server Action | `'use server'` export | `POST /path#fnName` |

경로 변환 정확도 9/9. `discover.js` 가 `app/` 또는 `pages/` 존재를 보고
Next 와 Express 를 자동 감지한다. 발견된 라우트는 그대로 불변식 I1~I6
검사 대상이 된다.

## 실전 검증 하니스 (1번)

이 개발 환경은 egress 차단(supabase.co, api.e2b.dev)과 자격증명 부재로
라이브 검증을 할 수 없다. `verify-live.js` 는 **사용자가 자기 키로** 세 가지
검증을 한 번에 돌리고 붙여넣을 리포트를 출력한다. 키는 저장하지 않는다.

```bash
node verify-live.js supabase <url> <anon-key> [userA-jwt userB-jwt]
node verify-live.js e2b      <e2b-api-key>
node verify-live.js app      <base> <loginPath> <emailA> <pwA> <emailB> <pwB>
node verify-live.js all      verify-live.config.json   # 템플릿: .example.json
```

각 모드가 확인하는 것:

- **supabase** — 실제 프로젝트의 테이블별 RLS 상태. 핵심 계약 검증도 안내:
  실제 Supabase 는 RLS 차단 시 401 이 아니라 200 [] 를 반환해야 한다.
  만약 'secure' 판정 테이블이 실제로 401/403 을 냈다면 어댑터 조정 필요.
- **e2b** — 실제 microVM 생성/실행/폐기. 네트워크 차단 실증: VM 안에서
  `fetch('https://example.com')` 가 실패해야 격리 성공.
- **app** — 배포된 실제 앱에 불변식 엔진 + 적대적 반증 + AutoTriage.

로컬 스모크(목 Supabase)로 하니스 자체는 검증했다. 남은 것은 사용자의
실제 키로 한 번 돌리는 것뿐이다.
