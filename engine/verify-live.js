'use strict';
/**
 * Live verification harness. Runs the three checks that this dev environment
 * cannot (egress-blocked + no credentials). You run it with your own keys; it
 * prints a report you can paste back for review.
 *
 *   node verify-live.js supabase <project-url> <anon-key> [userA-jwt userB-jwt]
 *   node verify-live.js e2b      <e2b-api-key>
 *   node verify-live.js app      <base-url> <loginPath> <emailA> <pwA> <emailB> <pwB>
 *   node verify-live.js all      <config.json>
 *
 * Nothing here is destructive by default. It never stores your keys.
 */
const fs = require('fs');

async function verifySupabase(base, anonKey, userA, userB) {
  const { audit } = require('./supabase');
  console.log(`\n▶ Supabase RLS  (${base})`);
  const r = await audit({ base, anonKey, probeWrite: true, userA: userA || null, userB: userB || null });
  console.log(`  tables: ${r.tablesFound}, confirmed: ${r.findings.filter(f=>f.verdict==='confirmed').length}, secure: ${r.secure.length}`);
  for (const f of r.findings.filter(f=>f.verdict==='confirmed'))
    console.log(`  ● ${f.severity}/5 ${f.table} — ${f.title}`);
  const modes = new Set(r.findings.map(f=>f.mode));
  console.log(`  detected modes: ${[...modes].join(', ') || 'none'}`);
  console.log(`  CONTRACT CHECK: real Supabase should return 200 [] (not 401) for RLS-blocked tables.`);
  console.log(`  If any 'secure' table above actually returned 401/403, the adapter needs adjustment.`);
  return r;
}

async function verifyE2B(apiKey) {
  console.log(`\n▶ E2B sandbox`);
  let mod; try { mod = require('e2b'); } catch { return console.log('  e2b SDK not installed: npm i e2b'); }
  const { E2BRunner } = require('./e2b-driver');
  const runner = new E2BRunner({ apiKey, timeoutMs: 30000, allowInternet: false });
  const t0 = Date.now();
  const out = await runner.runExploit({ script: `
    console.log('vm ok, uid=' + process.getuid?.());
    // network-off check: this fetch should FAIL inside an isolated microVM
    fetch('https://example.com').then(()=>console.log('NET: reachable (isolation FAILED)'))
      .catch(()=>console.log('NET: blocked (isolation OK)'))
      .finally(()=>console.log('done'));
  ` });
  console.log(`  create+run+kill in ${Date.now()-t0}ms, exitCode ${out.exitCode}`);
  console.log(`  stdout: ${out.stdout.trim().replace(/\n/g,' | ')}`);
  console.log(`  EXPECT: 'NET: blocked (isolation OK)' — proves the microVM had no internet.`);
  return out;
}

async function verifyApp(base, loginPath, emailA, pwA, emailB, pwB) {
  console.log(`\n▶ Live app scan  (${base})`);
  // reuse the invariant engine against a real deployed app
  const { discover } = require('./discover');
  const { ALL } = require('./invariants');
  const { falsify } = require('./adversary');
  const { triage } = require('./triage');
  const { Sandbox } = require('./sandbox');
  const box = new Sandbox({ allowHosts: [new URL(base).hostname], allowPrivate: false, maxRequests: 3000 });
  const login = async (email, password) => {
    const r = await box.fetch(base + loginPath, { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, password }) });
    const b = await r.json().catch(()=>({}));
    return { email, token: b.token || b.access_token || (b.session && b.session.access_token), id: b.user && (b.user.id) };
  };
  const routes = await discover({ base, sourceDir: null });
  const ctx = { base, probeIds: [1,2,3], allowDestructive: false,
    A: await login(emailA, pwA), B: await login(emailB, pwB), ADMIN: await login(emailB, pwB),
    get: async (p, token) => { const r = await box.fetch(base+p, { headers: token?{authorization:'Bearer '+token}:{} });
      let b=null; try{b=await r.json()}catch{} return { status:r.status, body:b }; } };
  const cand = [];
  for (const route of routes) for (const inv of ALL) await inv(ctx, route, cand);
  const conf = cand.filter(f=>f.verdict==='confirmed');
  const tested = await falsify(ctx, conf);
  const survived = tested.filter(f=>f.verdict==='confirmed');
  const tri = triage(survived);
  console.log(`  routes: ${routes.length}, candidates: ${conf.length}, survived adversary: ${survived.length}, clusters: ${tri.rows}`);
  for (const c of tri.clusters) console.log(`  ● ${c.severity}/5 ${c.route} — ${c.rootCause}`);
  console.log(`  requests used: ${box.used} (all to ${new URL(base).hostname})`);
  return tri;
}

(async () => {
  const [,, mode, ...a] = process.argv;
  try {
    if (mode === 'supabase') await verifySupabase(a[0], a[1], a[2], a[3]);
    else if (mode === 'e2b')  await verifyE2B(a[0]);
    else if (mode === 'app')  await verifyApp(a[0], a[1], a[2], a[3], a[4], a[5]);
    else if (mode === 'all') {
      const cfg = JSON.parse(fs.readFileSync(a[0], 'utf8'));
      if (cfg.supabase) await verifySupabase(cfg.supabase.url, cfg.supabase.anonKey, cfg.supabase.userA, cfg.supabase.userB);
      if (cfg.e2b)      await verifyE2B(cfg.e2b.apiKey);
      if (cfg.app)      await verifyApp(cfg.app.base, cfg.app.loginPath, cfg.app.emailA, cfg.app.pwA, cfg.app.emailB, cfg.app.pwB);
    } else {
      console.log('usage: node verify-live.js <supabase|e2b|app|all> ...args');
      console.log('  see the header of this file for each mode\'s arguments');
      process.exit(1);
    }
    console.log('\n✔ done — paste this output back for review.');
  } catch (e) { console.error('✗ error:', e.message); process.exit(1); }
})();
