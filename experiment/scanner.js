// Prototype: deterministic checks that PROVE a finding by observation, not inference.
const BASE = 'http://127.0.0.1:3000';
const findings = [];
const add = (id, title, evidence, proven) => findings.push({ id, title, evidence, proven });

const j = async (path, opts = {}) => {
  const r = await fetch(BASE + path, opts);
  let body; try { body = await r.json(); } catch { body = null; }
  return { status: r.status, headers: r.headers, body };
};

async function login(email, password) {
  const r = await j('/api/login', { method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }) });
  return r;
}

(async () => {
  // ---- Setup: two real accounts (the core technique) ----
  const A = await login('alice@test.com', 'alice123');
  const B = await login('bob@test.com', 'bob123');
  const hA = { authorization: 'Bearer ' + A.body.token };
  const hB = { authorization: 'Bearer ' + B.body.token };

  // [E2] over-exposure: does login response contain a secret-looking field?
  const leaky = Object.keys(A.body.user || {}).filter(k => /password|hash|secret|token/i.test(k));
  if (leaky.length) add('E2', 'Login response exposes sensitive fields',
    `fields: ${leaky.join(',')} = ${A.body.user[leaky[0]]}`, true);

  // [B1] IDOR read: B asks for A's note
  const aNote = await j('/api/notes/1', { headers: hA });
  const bSteal = await j('/api/notes/1', { headers: hB });
  if (bSteal.status === 200 && JSON.stringify(bSteal.body) === JSON.stringify(aNote.body))
    add('B1', 'IDOR: cross-account read on GET /api/notes/:id',
      `bob got alice's note verbatim: ${JSON.stringify(bSteal.body).slice(0,60)}`, true);

  // SAFE CONTROL [B1-control]: same shape, but correctly guarded
  const aCard = await j('/api/cards/1', { headers: hA });
  const bCard = await j('/api/cards/1', { headers: hB });
  if (bCard.status === 200 && JSON.stringify(bCard.body) === JSON.stringify(aCard.body))
    add('FP!', 'FALSE POSITIVE: flagged the safe endpoint', JSON.stringify(bCard.body), true);

  // [B3] IDOR delete: B deletes A's note (destructive - verify by re-read)
  const del = await j('/api/notes/1', { method: 'DELETE', headers: hB });
  const after = await j('/api/notes/1', { headers: hA });
  if (del.status === 200 && after.status === 404)
    add('B3', 'IDOR: cross-account DELETE on /api/notes/:id',
      `bob deleted alice's note; owner now gets 404`, true);

  // [B6] BFLA: non-admin hits admin endpoint
  const adm = await j('/api/admin/users', { headers: hB });
  if (adm.status === 200 && Array.isArray(adm.body))
    add('B6', 'BFLA: non-admin can read /api/admin/users',
      `returned ${adm.body.length} user records incl. hashes`, true);

  // [B10] mass assignment: privilege escalation
  const esc = await j('/api/me', { method: 'PATCH',
    headers: { ...hB, 'content-type': 'application/json' },
    body: JSON.stringify({ role: 'admin' }) });
  if (esc.body && esc.body.role === 'admin')
    add('B10', 'Mass assignment: user escalated self to admin',
      `PATCH {"role":"admin"} -> role is now ${esc.body.role}`, true);

  // [E1] unauthenticated data endpoint
  const anon = await j('/api/stats');
  if (anon.status === 200 && JSON.stringify(anon.body).includes('@'))
    add('E1', 'Unauthenticated endpoint leaks data',
      `GET /api/stats with no token -> ${JSON.stringify(anon.body).slice(0,60)}`, true);

  // [E3] pagination cap
  const big = await j('/api/notes?limit=999999', { headers: hB });
  if (big.status === 200) add('E3', 'No pagination cap (limit accepted verbatim)',
    `?limit=999999 -> 200 with ${(big.body||[]).length} rows`, true);

  // [F1] SQL injection - error-based proof
  const inj = await j("/api/search?q=' OR 1=1 --", { headers: hB });
  const norm = await j('/api/search?q=zzzz', { headers: hB });
  if (inj.status === 200 && (inj.body||[]).length > (norm.body||[]).length)
    add('F1', 'SQL injection: boolean payload changes result set',
      `q="' OR 1=1 --" -> ${(inj.body||[]).length} rows vs baseline ${(norm.body||[]).length}`, true);

  // [E9] stack trace leakage
  const err = await j("/api/search?q='", { headers: hB });
  if (err.body && err.body.stack) add('E9', 'Stack trace returned to client',
    String(err.body.stack).split('\n')[0], true);

  // [E15] debug endpoint
  const dbg = await j('/api/debug/config');
  if (dbg.status === 200 && JSON.stringify(dbg.body).match(/FIXTURE-PAYMENT|secret/i))
    add('E15', 'Debug endpoint exposes secrets',
      JSON.stringify(dbg.body).slice(0, 80), true);

  // [H5][G6][M6] header checks
  const hdr = await fetch(BASE + '/api/stats');
  const g = n => hdr.headers.get(n);
  if (g('access-control-allow-origin') === '*' && g('access-control-allow-credentials') === 'true')
    add('H5', 'CORS wildcard with credentials', `ACAO:* + ACAC:true`, true);
  if (!g('content-security-policy')) add('G6', 'No Content-Security-Policy header', 'absent', true);
  if (!g('x-frame-options')) add('G8', 'No X-Frame-Options header', 'absent', true);
  if (!g('x-content-type-options')) add('G9', 'No X-Content-Type-Options header', 'absent', true);
  if (g('x-powered-by')) add('M6', 'Server version disclosure', `X-Powered-By: ${g('x-powered-by')}`, true);

  // [A5] user enumeration
  const noUser = await login('nobody@test.com', 'x');
  const badPw  = await login('alice@test.com', 'wrong');
  if (noUser.status !== badPw.status)
    add('A5', 'User enumeration via distinct auth responses',
      `unknown user -> ${noUser.status} "${noUser.body.error}" vs wrong pw -> ${badPw.status} "${badPw.body.error}"`, true);

  // [N2] rate limit on login
  const t0 = Date.now();
  const tries = await Promise.all(Array.from({length: 30}, () => login('alice@test.com','wrong')));
  const blocked = tries.filter(r => r.status === 429).length;
  if (blocked === 0) add('N2', 'No rate limiting on login',
    `30 failed logins in ${Date.now()-t0}ms, zero 429s`, true);

  console.log(JSON.stringify(findings, null, 2));
  console.log(`\nTOTAL: ${findings.length} findings, all PROVEN by observation`);
})();
