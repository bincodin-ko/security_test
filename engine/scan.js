'use strict';
/** Full pipeline: recon -> parallel hunt -> ledger -> fix plan -> independent verify. */
const { discover } = require('./discover');
const { ALL } = require('./invariants');
const { pool } = require('./pool');
const ledger = require('./ledger');
const watch = require('./watch');
const { plan: fixPlan } = require('./fix');
const { verifyAll } = require('./verify');
const { falsify } = require('./adversary');
const { triage } = require('./triage');
const { exportAll } = require('./mcp-export');
const { Sandbox } = require('./sandbox');
const fs = require('fs');

const BASE = process.env.BASE || 'http://127.0.0.1:3000';
const SRC  = process.env.SRC  || '../experiment/vulnapp';
const STATE = process.env.STATE || '/tmp/scanstate';
const DESTRUCTIVE = process.env.DESTRUCTIVE === '1';

const login = async (email, password) => {
  const r = await fetch(BASE + '/api/login', { method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }) });
  const b = await r.json();
  return { email, token: b.token, id: b.user && b.user.id };
};

(async () => {
  fs.mkdirSync(STATE, { recursive: true });
  const box = new Sandbox({ allowHosts: [new URL(BASE).hostname], allowPrivate: true });

  // 1. RECON
  const routes = await discover({ base: BASE, sourceDir: SRC });
  const surface = watch.diffSurface(`${STATE}/surface.json`, routes);
  const sched = watch.plan({ trigger: 'deploy', surface, hoursSinceFull: 99 });

  const ctx = { base: BASE, probeIds: [1, 2, 3], allowDestructive: DESTRUCTIVE,
    A: await login('alice@test.com', 'alice123'),
    B: await login('bob@test.com', 'bob123'),
    ADMIN: await login('admin@test.com', 'admin123'),
    get: async (p, token) => {
      const r = await box.fetch(BASE + p, { headers: token ? { authorization: 'Bearer ' + token } : {} });
      let body = null; try { body = await r.json(); } catch {}
      return { status: r.status, body };
    },
    send: async (p, token, payload) => {
      const [method, path] = p.includes(' ') ? p.split(' ') : ['PATCH', p];
      const r = await box.fetch(BASE + path, { method,
        headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}) },
        body: JSON.stringify(payload) });
      let body = null; try { body = await r.json(); } catch {}
      return { status: r.status, body };
    } };

  // 2. PARALLEL HUNT - fresh findings array per route, workers retired after each
  let done = 0;
  const chunks = await pool(routes, async route => {
    const out = [];
    for (const inv of ALL) await inv(ctx, route, out);
    return out;
  }, { concurrency: 6, onProgress: d => { done = d; } });
  const findings = chunks.flat();
  const rawConfirmed = findings.filter(f => f.verdict === 'confirmed');

  // ADVERSARIAL DISPROVE - independent module re-derives each attack and tries
  // to falsify it. Only survivors stay confirmed.
  const tested = await falsify(ctx, rawConfirmed);
  const confirmed = tested.filter(f => f.verdict === 'confirmed');
  const falsified = tested.filter(f => f.verdict === 'rejected');
  const needs = [...findings.filter(f => f.verdict === 'needs_validation'),
                 ...tested.filter(f => f.verdict === 'needs_validation')];
  const rejected = findings.filter(f => f.verdict === 'rejected');

  // 3. LEDGER - accumulate across runs
  const delta = ledger.record(`${STATE}/ledger.json`, {
    coveredUnits: routes.map(r => `${r.method} ${r.path}`), confirmed });

  // AUTOTRIAGE - one row per root cause
  const tri = triage(confirmed);

  // 4. FIX PLAN  5. INDEPENDENT VERIFY (separate module, never saw the hunt)
  const reds = fixPlan(confirmed);
  const verified = await verifyAll(ctx, confirmed);
  const stillOpen = verified.filter(v => v.verification.fixed === false).length;
  const nowFixed = verified.filter(v => v.verification.fixed === true).length;

  const handoff = exportAll(confirmed, reds);
  fs.writeFileSync(`${STATE}/handoff.json`, JSON.stringify(handoff, null, 2));

  console.log(`
┌─ RECON ──────────────────────────────────────────────`);
  console.log(`│ routes discovered  ${routes.length}   surface ${surface.first ? 'baseline' : surface.changed ? 'CHANGED' : 'unchanged'}`);
  if (surface.added.length) console.log(`│ new endpoints      ${surface.added.join(', ')}`);
  console.log(`│ scheduler says     ${sched.scope}  (${sched.why})`);
  console.log(`├─ HUNT (parallel, ${6} workers) ──────────────────────`);
  console.log(`│ candidates ${rawConfirmed.length}`);
  console.log(`├─ ADVERSARIAL DISPROVE (independent) ────────────────`);
  console.log(`│ survived ${confirmed.length}   falsified ${falsified.length}`);
  console.log(`├─ AUTOTRIAGE ────────────────────────────────────────`);
  console.log(`│ ${confirmed.length} findings -> ${tri.rows} root-cause clusters (dedupe ${Math.round(tri.dedupeRatio*100)}%)`);
  console.log(`├─ LEDGER (run #${delta.run}) ─────────────────────────────`);
  console.log(`│ new ${delta.isNew.length}   persisting ${delta.persisting.length}   fixed ${delta.fixed.length}   cumulative open ${delta.cumulative}`);
  console.log(`├─ FIX PLAN ──────────────────────────────────────────`);
  console.log(`│ ${reds.length} regression tests generated`);
  console.log(`├─ INDEPENDENT VERIFY ────────────────────────────────`);
  console.log(`│ still exploitable ${stillOpen}   now blocked ${nowFixed}`);
  console.log(`├─ SANDBOX ───────────────────────────────────────────`);
  console.log(`│ ${box.used} requests, all to allow-listed host only`);
  console.log(`└─ handoff written to ${STATE}/handoff.json`);
  fs.writeFileSync(`${STATE}/last.json`, JSON.stringify({ confirmed, needs, rejected, delta }, null, 2));
})();
