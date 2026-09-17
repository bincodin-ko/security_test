'use strict';
/**
 * Live scan server — connects the real engine to the 가드레일 UI.
 *
 *   GET /                served the built single-page UI (bundle.html)
 *   GET /api/health      { ok, target }
 *   GET /api/scan (SSE)  runs discover → invariants → adversary → triage → fix
 *                        → verify against a real target and streams the run:
 *                          event: stage    {stage,i,total}
 *                          event: log      {kind,text}
 *                          event: progress {done,total}
 *                          event: done     {result}
 *
 * No web framework — plain http, so the engine has zero runtime deps.
 * Every route, verdict, count, evidence, RED test and verify result in the
 * response is produced by the engine modules below, not hand-written.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const { discover } = require('./discover');
const { ALL } = require('./invariants');
const { pool } = require('./pool');
const { falsify } = require('./adversary');
const { triage } = require('./triage');
const { plan: fixPlan } = require('./fix');
const { verifyAll } = require('./verify');
const { Sandbox } = require('./sandbox');
const supa = require('./supabase');

const PORT = +(process.env.PORT || 4000);
const DEMO_BASE = process.env.DEMO_BASE || 'http://127.0.0.1:3000';
const DEMO_SRC = path.join(__dirname, '..', 'experiment', 'vulnapp');
const UI_FILE = path.join(__dirname, '..', 'design', 'guardrail-app', 'bundle.html');

/* ── friendly Korean presentation layer ────────────────────────────────────
   Localises the engine's own findings. Titles/causes are keyed off the
   invariant the engine tripped; the route, evidence, counts, RED test and
   verify status underneath are the engine's real output, unchanged. */
const INV_KO = {
  I1: { t: '다른 계정의 리소스가 그대로 읽힙니다', c: '소유권 검사가 없습니다 — 행을 불러온 뒤 owner를 인증 사용자와 비교해 다르면 403/404를 반환하세요.' },
  I2: { t: '권한 낮은 사용자가 운영자 범위 데이터를 봅니다', c: '역할·소유 범위 검사가 없습니다 — 쿼리를 호출자 소유로 좁히거나 역할 게이트를 두세요.' },
  I3: { t: '로그인 없이 사용자 데이터가 나옵니다', c: '인증 미들웨어가 빠졌습니다 — 보호 라우터 밖에 등록된 라우트를 확인하세요.' },
  I4: { t: '클라이언트가 보낸 권한 필드를 서버가 그대로 믿습니다', c: '수정 가능한 필드를 allow-list 하세요 — 요청 바디를 그대로 펼쳐 넣지 마세요.' },
  I5: { t: '돈·권한 상태가 뒤로 되돌아갈 수 있습니다', c: '서버에서 허용된 상태 전이만 강제하세요.' },
  I6: { t: '서버 전용 값이 클라이언트로 나갑니다', c: 'SELECT * 대신 필요한 컬럼만, 또는 공용 시리얼라이저로 민감 필드를 거르세요.' },
};
const SRC_KO = { I1: 'IDOR · 2계정', I2: 'BFLA · 권한', I3: '익명 접근', I4: '매스 어사인먼트', I5: '상태 전이', I6: '시크릿 노출' };

function splitRoute(r) { const i = r.indexOf(' '); return i < 0 ? ['GET', r] : [r.slice(0, i), r.slice(i + 1)]; }

function presentCluster(cl, fixByRoute) {
  const [method, route] = splitRoute(cl.route);
  const primary = cl.invariants[0];
  const ko = INV_KO[primary] || { t: cl.primary, c: cl.rootCause };
  const red = fixByRoute.get(cl.route);
  return {
    inv: cl.invariants,
    method, route,
    title: ko.t,
    src: SRC_KO[primary] || primary,
    cause: ko.c,
    ev0: '실제 요청에서 관측된 응답:',
    ev1: Sandbox.redact(String(cl.evidence || '')).slice(0, 160),
    fix: `"${cl.route}" ${ko.c} 이 검사는 서버 측에서 모든 메서드에 적용하고, 다른 검사를 약화시키지 마세요.`,
    red: red ? red.code : null,
  };
}

/* ── run one scan, streaming events through `emit` ─────────────────────────*/
async function runScan({ base, sourceDir, destructive, supabase }, emit) {
  const STAGES = ['라우트 발견', '불변식 I1–I6 검사', '적대적 반증', '격리 증명', '결과 정리'];
  const stage = (i) => emit('stage', { stage: STAGES[i], i, total: STAGES.length });
  const box = new Sandbox({ allowHosts: [new URL(base).hostname], allowPrivate: true });

  const login = async (email, password) => {
    try {
      const r = await fetch(base + '/api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, password }) });
      const b = await r.json(); return { email, token: b.token, id: b.user && b.user.id };
    } catch { return { email, token: null, id: null }; }
  };

  // 1. RECON
  stage(0);
  const routes = await discover({ base, sourceDir });
  emit('log', { kind: 'accent', text: `  discover · ${routes.length} routes found` });
  emit('progress', { done: 0, total: routes.length });

  const ctx = {
    base, probeIds: [1, 2, 3], allowDestructive: destructive,
    A: await login('alice@test.com', 'alice123'),
    B: await login('bob@test.com', 'bob123'),
    ADMIN: await login('admin@test.com', 'admin123'),
    get: async (p, token) => { const r = await box.fetch(base + p, { headers: token ? { authorization: 'Bearer ' + token } : {} }); let body = null; try { body = await r.json(); } catch {} return { status: r.status, body }; },
    send: async (p, token, payload) => { const [m, pt] = p.includes(' ') ? p.split(' ') : ['PATCH', p]; const r = await box.fetch(base + pt, { method: m, headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}) }, body: JSON.stringify(payload) }); let body = null; try { body = await r.json(); } catch {} return { status: r.status, body }; },
  };

  // 2. HUNT (parallel; each route gets a fresh findings array)
  stage(1);
  const chunks = await pool(routes, async (route) => {
    const out = [];
    for (const inv of ALL) await inv(ctx, route, out);
    for (const f of out) {
      const [m, p] = splitRoute(f.route);
      if (f.verdict === 'confirmed') emit('log', { kind: 'crit', text: `  → ${m} ${p}  ${f.inv} BROKEN — ${Sandbox.redact(String(f.evidence || '')).slice(0, 48)}` });
      else if (f.verdict === 'needs_validation') emit('log', { kind: 'warn', text: `  ? ${m} ${p}  ${f.inv} needs review` });
      else emit('log', { kind: '', text: `  ✓ ${m} ${p}  ${f.inv} holds` });
    }
    return out;
  }, { concurrency: 6, onProgress: (d, t) => emit('progress', { done: d, total: t }) });
  const findings = chunks.flat();
  const rawConfirmed = findings.filter((f) => f.verdict === 'confirmed');

  // 3. ADVERSARIAL DISPROVE
  stage(2);
  emit('log', { kind: 'accent', text: `  adversary · re-deriving ${rawConfirmed.length} candidates` });
  const tested = await falsify(ctx, rawConfirmed);
  const confirmed = tested.filter((f) => f.verdict === 'confirmed');
  const falsified = tested.filter((f) => f.verdict === 'rejected');
  emit('log', { kind: 'accent', text: `  adversary · survived ${confirmed.length}, falsified ${falsified.length}` });

  // 4. ISOLATED PROOF + TRIAGE
  stage(3);
  emit('log', { kind: '', text: `  sandbox · ${box.used} requests, allow-listed host only` });
  stage(4);
  const tri = triage(confirmed);
  const reds = fixPlan(confirmed);
  const verified = await verifyAll(ctx, confirmed);
  const openN = verified.filter((v) => v.verification.fixed === false).length;
  const fixedN = verified.filter((v) => v.verification.fixed === true).length;
  emit('log', { kind: 'pass', text: `  ✓ confirmed ${confirmed.length} → ${tri.rows} clusters · noise −${Math.round(tri.dedupeRatio * 100)}%` });

  const fixByRoute = new Map(reds.map((r) => [r.route, r]));
  const clusters = tri.clusters.map((c) => presentCluster(c, fixByRoute));

  // Supabase RLS (optional)
  let supaResult = null;
  if (supabase && supabase.anonKey) {
    emit('log', { kind: 'accent', text: `  supabase · RLS scan on ${supabase.base}` });
    try {
      const r = await supa.audit({ base: supabase.base, anonKey: supabase.anonKey, probeWrite: false, userA: supabase.userA || null, userB: supabase.userB || null });
      supaResult = r;
      for (const f of r.findings.filter((f) => f.verdict === 'confirmed')) {
        clusters.push({ inv: ['RLS'], method: 'TABLE', route: f.table, title: '로그인한 누구나 이 테이블을 읽습니다', src: 'Supabase RLS · 2계정', cause: 'RLS 정책이 "소유"가 아니라 "로그인 여부"만 검사합니다.', ev0: 'anon 키로 조회한 결과:', ev1: Sandbox.redact(String(f.evidence || '')).slice(0, 160), fix: f.fix, red: null });
      }
    } catch (e) { emit('log', { kind: 'warn', text: `  supabase · ${String(e.message || e)}` }); }
  }

  const NEEDS_KO = {
    'Admin-named route answers a regular user': '관리자용 이름의 라우트가 일반 사용자에게 응답합니다',
    'Write route not probed for mass assignment': '쓰기 라우트를 매스 어사인먼트로 검사하지 못했습니다',
    'Mutating route with id param not tested': 'id 파라미터가 있는 변경 라우트를 검사하지 못했습니다',
    'State-changing route on a money/permission object': '돈·권한 객체를 바꾸는 라우트입니다',
    'Unauthenticated access returns a payload': '로그인 없이 응답이 나옵니다 (공개 의도인지 확인 필요)',
  };
  const NEEDS_WHY_KO = {
    'destructive test disabled': '쓰기 테스트 꺼짐 — 켜면 확정',
    'destructive test disabled; cannot confirm ownership enforcement': '쓰기 테스트 꺼짐 — 켜면 소유권 확정',
    'path suggests operator scope but payload shows no ownership markers': '경로는 운영자용이나 소유 표식이 없음 — 판단 필요',
    'only the app owner knows which transitions are legal': '허용 전이는 앱 주인만 압니다',
    'cannot tell whether this payload is meant to be public': '공개 의도인지 판단 필요',
  };
  const koWhyPass = (ev) => /got 200.*got 403|got 200.*got 404/.test(ev) ? '주인만 200, 남은 403/404 — 격리 유지' : /public endpoint/i.test(ev) ? '의도된 공개 엔드포인트' : /no privileged content/i.test(ev) ? '민감 데이터 없음' : ev;
  const needs = findings.filter((f) => f.verdict === 'needs_validation').map((f) => { const [m, p] = splitRoute(f.route); return { method: m, route: p, title: NEEDS_KO[f.title] || f.title, why: NEEDS_WHY_KO[f.unresolved] || f.unresolved || '' }; });
  const passed = findings.filter((f) => f.verdict === 'rejected').map((f) => { const [m, p] = splitRoute(f.route); return { method: m, route: p, title: /Isolation holds/i.test(f.title) ? '소유권 검사가 제대로 있습니다' : /no privileged content/i.test(f.title) ? '모두 같은 응답이지만 민감 데이터 없음' : f.title, why: koWhyPass(f.evidence || '') }; });

  return {
    live: true, target: base, withSupabase: !!supaResult,
    meta: { routes: routes.length, candidates: rawConfirmed.length, confirmed: confirmed.length, clusters: clusters.length, dedupe: Math.round(tri.dedupeRatio * 100), verifyOpen: openN, verifyFixed: fixedN, sandboxReqs: box.used, tables: supaResult ? supaResult.tablesFound : null },
    clusters, needs, passed,
    coverage: { supabaseRan: !!supaResult, destructiveRan: !!destructive },
  };
}

/* ── demo fixture lifecycle ────────────────────────────────────────────────*/
let fixture = null;
async function up(base) { try { await fetch(base + '/api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }); return true; } catch { return false; } }
async function ensureFixture() {
  if (await up(DEMO_BASE)) return;
  fixture = spawn('node', ['server.js'], { cwd: DEMO_SRC, stdio: 'ignore', detached: false });
  for (let i = 0; i < 40; i++) { if (await up(DEMO_BASE)) return; await new Promise((r) => setTimeout(r, 150)); }
  throw new Error('demo fixture failed to start');
}

/* ── http server ───────────────────────────────────────────────────────────*/
const server = http.createServer(async (rq, rs) => {
  const u = new URL(rq.url, `http://localhost:${PORT}`);

  if (u.pathname === '/api/health') { rs.writeHead(200, { 'content-type': 'application/json' }); return rs.end(JSON.stringify({ ok: true, target: DEMO_BASE })); }

  if (u.pathname === '/api/scan') {
    rs.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive', 'access-control-allow-origin': '*' });
    const emit = (event, data) => { try { rs.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`); } catch {} };
    const targetParam = u.searchParams.get('target') || 'demo';
    const supabaseKey = u.searchParams.get('supabaseKey');
    const supabaseUrl = u.searchParams.get('supabaseUrl');
    try {
      let base = DEMO_BASE;
      if (targetParam === 'demo') await ensureFixture();
      else base = /^https?:\/\//.test(targetParam) ? targetParam : `https://${targetParam}`;
      const supabase = supabaseKey ? { base: supabaseUrl, anonKey: supabaseKey } : null;
      const result = await runScan({ base, sourceDir: targetParam === 'demo' ? DEMO_SRC : null, destructive: u.searchParams.get('destructive') === '1', supabase }, emit);
      emit('done', { result });
    } catch (e) { emit('error', { message: String(e && e.message || e) }); }
    return rs.end();
  }

  // static UI
  if (u.pathname === '/' || u.pathname === '/index.html') {
    fs.readFile(UI_FILE, (err, buf) => {
      if (err) { rs.writeHead(500, { 'content-type': 'text/plain' }); return rs.end('bundle.html not built — run the bundler in design/guardrail-app'); }
      rs.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); rs.end(buf);
    });
    return;
  }
  rs.writeHead(404); rs.end('not found');
});

server.listen(PORT, () => console.log(`가드레일 live server · http://127.0.0.1:${PORT}  (target ${DEMO_BASE})`));
process.on('SIGTERM', () => { if (fixture) try { fixture.kill(); } catch {} process.exit(0); });
