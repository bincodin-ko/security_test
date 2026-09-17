'use strict';
/**
 * Pre-deploy security gate (VibeGuard-style). Run in CI or a git pre-push hook:
 * it scans the target, applies a policy, and EXITS NON-ZERO to block the deploy
 * when confirmed vulnerabilities remain. Green only when the pipeline agrees.
 *
 *   node gate.js <base-url> [--src <dir>] [--login <path>] [--destructive]
 * Policy via env:
 *   GATE_FAIL_ON        confirmed | none        (default: confirmed)
 *   GATE_MAX_SEVERITY   block if any confirmed >= N (default: 1 = any)
 *   GATE_ALLOW          comma list of "INV route" to waive (known/accepted)
 */
const { discover } = require('./discover');
const { ALL } = require('./invariants');
const { falsify } = require('./adversary');
const { triage } = require('./triage');
const { Sandbox } = require('./sandbox');

const BASE = process.argv[2] || process.env.BASE || 'http://127.0.0.1:3000';
const arg = (f) => { const i = process.argv.indexOf(f); return i > -1 ? process.argv[i+1] : null; };
const SRC = arg('--src');
const LOGIN = arg('--login') || '/api/login';
const DESTRUCTIVE = process.argv.includes('--destructive');
const FAIL_ON = process.env.GATE_FAIL_ON || 'confirmed';
const MAX_SEV = parseInt(process.env.GATE_MAX_SEVERITY || '1', 10);
const ALLOW = new Set((process.env.GATE_ALLOW || '').split(',').map(s => s.trim()).filter(Boolean));

async function login(box, email, password) {
  const r = await box.fetch(BASE + LOGIN, { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, password }) });
  const b = await r.json().catch(() => ({}));
  return { email, token: b.token || b.access_token || (b.session && b.session.access_token), id: b.user && b.user.id };
}

(async () => {
  const t0 = Date.now();
  const box = new Sandbox({ allowHosts: [new URL(BASE).hostname], allowPrivate: true, maxRequests: 5000 });
  const routes = await discover({ base: BASE, sourceDir: SRC });
  const ctx = { base: BASE, probeIds: [1, 2, 3], allowDestructive: DESTRUCTIVE,
    A: await login(box, 'alice@test.com', 'alice123'),
    B: await login(box, 'bob@test.com', 'bob123'),
    ADMIN: await login(box, 'admin@test.com', 'admin123'),
    get: async (p, tok) => { const r = await box.fetch(BASE + p, { headers: tok ? { authorization: 'Bearer ' + tok } : {} });
      let b = null; try { b = await r.json(); } catch {} return { status: r.status, body: b }; } };

  const cand = [];
  for (const route of routes) for (const inv of ALL) await inv(ctx, route, cand);
  const confirmed = (await falsify(ctx, cand.filter(f => f.verdict === 'confirmed')))
    .filter(f => f.verdict === 'confirmed');
  const tri = triage(confirmed);

  // apply policy: waive allow-listed, keep those at/above severity threshold
  const blocking = tri.clusters.filter(c =>
    c.severity >= MAX_SEV &&
    !c.invariants.every(inv => ALLOW.has(`${inv} ${c.route}`)));

  const pass = FAIL_ON === 'none' ? true : blocking.length === 0;
  const dur = ((Date.now() - t0) / 1000).toFixed(1);

  console.log(`\n╔════ 가드레일 배포 게이트 ════`);
  console.log(`║ 대상   ${BASE}`);
  console.log(`║ 라우트 ${routes.length}  ·  확정 ${confirmed.length}  ·  클러스터 ${tri.rows}  ·  ${dur}s`);
  console.log(`║ 정책   fail-on=${FAIL_ON}  min-severity=${MAX_SEV}  waived=${ALLOW.size}`);
  console.log(`╠${'─'.repeat(30)}`);
  if (blocking.length) {
    for (const c of blocking) console.log(`║ ✗ ${c.severity}/5  ${c.route}  —  ${c.rootCause.slice(0,54)}`);
  } else {
    console.log(`║ 차단할 확정 취약점 없음`);
  }
  console.log(`╚════ ${pass ? '\x1b[32m배포 허용 (PASS)\x1b[0m' : '\x1b[31m배포 차단 (FAIL)\x1b[0m'} ════\n`);

  require('fs').writeFileSync(process.env.GATE_OUT || '/tmp/gate-result.json',
    JSON.stringify({ pass, target: BASE, routes: routes.length, confirmed: confirmed.length,
      blocking: blocking.map(c => ({ severity: c.severity, route: c.route, cause: c.rootCause })) }, null, 2));

  process.exit(pass ? 0 : 1);
})().catch(e => { console.error('gate error:', e.message); process.exit(2); });
