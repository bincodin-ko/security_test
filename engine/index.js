'use strict';
const { discover } = require('./discover');
const { ALL } = require('./invariants');

const BASE = process.env.BASE || 'http://127.0.0.1:3000';
const SRC  = process.env.SRC  || '../experiment/vulnapp';
const DESTRUCTIVE = process.env.DESTRUCTIVE === '1';

async function login(email, password) {
  const r = await fetch(BASE + '/api/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }) });
  const b = await r.json();
  return { email, token: b.token, id: b.user && b.user.id };
}

(async () => {
  const routes = await discover({ base: BASE, sourceDir: SRC });
  const ctx = {
    base: BASE,
    A:     await login('alice@test.com', 'alice123'),
    B:     await login('bob@test.com',   'bob123'),
    ADMIN: await login('admin@test.com', 'admin123'),
    probeIds: [1, 2, 3],
    allowDestructive: DESTRUCTIVE,
  };

  const findings = [];
  for (const route of routes)
    for (const inv of ALL) await inv(ctx, route, findings);

  const by = v => findings.filter(f => f.verdict === v);
  const out = { scanned: routes.length, destructive: DESTRUCTIVE,
                confirmed: by('confirmed'), needs_validation: by('needs_validation'),
                rejected: by('rejected') };

  console.log(`\n  routes discovered : ${routes.length}`);
  console.log(`  destructive mode  : ${DESTRUCTIVE ? 'ON' : 'OFF (read-only, safe)'}\n`);
  for (const f of out.confirmed)
    console.log(`  \x1b[31mCONFIRMED\x1b[0m [${f.inv}] ${f.route}\n      ${f.title}\n      ${f.evidence}\n`);
  for (const f of out.needs_validation)
    console.log(`  \x1b[33mNEEDS CHECK\x1b[0m [${f.inv}] ${f.route}\n      ${f.title}\n      ? ${f.unresolved}\n`);
  console.log(`  \x1b[32mPASSED\x1b[0m ${out.rejected.length} boundary checks held`);
  console.log(`\n  ${out.confirmed.length} confirmed / ${out.needs_validation.length} need check / ${out.rejected.length} passed`);
  require('fs').writeFileSync('/tmp/engine-out.json', JSON.stringify(out, null, 2));
})();
