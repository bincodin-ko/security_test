# 배포 전 보안 게이트

배포하기 전에 스캔을 돌려 **확정 취약점이 있으면 배포를 막는다**(exit 1).
녹색은 파이프라인이 통과를 동의할 때만 나온다.

## 실행

```bash
node engine/gate.js <base-url> [--src <dir>] [--login <path>] [--destructive]
```

정책은 환경변수로:

| 변수 | 뜻 | 기본 |
|---|---|---|
| `GATE_FAIL_ON` | `confirmed`면 확정 취약점에 실패, `none`이면 리포트만 | confirmed |
| `GATE_MAX_SEVERITY` | 이 심각도 이상만 차단 | 1 (전부) |
| `GATE_ALLOW` | `"INV route"` 콤마목록 — 검토 후 승인한 항목 waive | 없음 |

## 검증

취약한 테스트 앱 → **배포 차단(exit 1)**. 취약점 6개를 고치자 → **배포 허용(exit 0)**.
고치는 과정에서 놓친 `/api/notes` 목록 필터 누락도 게이트가 잡아냈다 — 사람이
"다 고쳤다"고 생각한 뒤에도 남은 것을 잡는 것이 게이트의 목적이다.

```
취약 상태:  라우트 13 · 확정 6 · 배포 차단 (FAIL)  exit 1
수정 후:    라우트 13 · 확정 0 · 배포 허용 (PASS)  exit 0
```

## 통합

- **GitHub Action**: `.github/workflows/guardrail.yml` — PR·main push에서 자동 실행.
  앱 기동 방식은 프로젝트에 맞게 수정.
- **git pre-push 훅**: `engine/hooks/pre-push` — 로컬 푸시 전 검사.
  설치: `cp engine/hooks/pre-push .git/hooks/ && chmod +x .git/hooks/pre-push`

두 경우 모두 exit 1이면 배포/머지가 막힌다. 검토 후 받아들인 위험은
`GATE_ALLOW`로 명시적으로 승인한다(조용히 무시하지 않음).
