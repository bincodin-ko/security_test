# 가드레일 — live app (engine ↔ UI)

The UI in `design/guardrail-app` is wired to the real scan engine here. Same
UI, two runtime modes:

| mode | when | data |
|------|------|------|
| **live** | served by `engine/server.js` (same origin) | the real engine scans a target and streams the run |
| **demo** | opened standalone (e.g. as a claude.ai artifact) | built-in example data + a scripted animation (fallback when no `/api/scan` backend answers) |

## Run it

```bash
cd engine
./run-live.sh          # → http://127.0.0.1:4000
```

Click **진단** with the default URL to scan the bundled vulnerable fixture
(`experiment/vulnapp`) with the real engine. Put a real URL in the box to scan
your own app (needs outbound network). Add a Supabase **anon** key to include
the RLS audit.

## How the connection works

`server.js` (zero deps, plain `http`):

- `GET /` — serves `design/guardrail-app/bundle.html`
- `GET /api/scan` (SSE) — runs the real pipeline and streams it:
  `discover → invariants (I1–I6) → adversary disprove → triage → fix plan → verify`,
  emitting `stage` / `log` / `progress` events and a final `done` with the result.

Everything the UI shows in live mode — routes, verdicts, counts, redacted
evidence, the RED regression test, the verify status, the dedupe ratio, the
sandbox request count — is the engine's real output. A thin Korean
presentation layer localises titles/causes; the underlying facts are unchanged.

The frontend opens an `EventSource` to `/api/scan`; if nothing answers within
1.5 s (no backend) it falls back to demo mode, so the same `bundle.html` works
as a standalone artifact.

## Rebuild the UI bundle after editing the React source

```bash
cd design/guardrail-app && bash build-bundle.sh
```
