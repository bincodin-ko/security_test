'use strict';
/**
 * Mock Supabase PostgREST endpoint. LOCAL ONLY test fixture.
 * Mimics the real REST surface an anon key hits:
 *   GET  /rest/v1/            -> OpenAPI spec listing tables (table discovery)
 *   GET  /rest/v1/<table>     -> rows, subject to that table's RLS state
 *   POST /rest/v1/<table>     -> insert, subject to RLS
 * Auth headers: apikey + Authorization: Bearer <key>
 *
 * Each table is planted in one of the five RLS failure modes so the adapter
 * can be measured against ground truth.
 */
const http = require('http');

const ANON = 'anon_pk_test_0000';
const SERVICE = 'service_role_test_0000';
// two logged-in user tokens (real Supabase: JWTs with a `sub` claim = user id)
const USER_A = 'user_jwt_alice';   // maps to owner 1
const USER_B = 'user_jwt_bob';     // maps to owner 2
const USERID = { [USER_A]: 1, [USER_B]: 2 };

// Ground-truth RLS states. mode = what's wrong (or 'secure').
const TABLES = {
  // 1. RLS OFF - anon reads everything. #1 real-world cause.
  profiles:  { mode: 'rls_off', rows: [
    { id: 1, email: 'alice@x.com', full_name: 'Alice', stripe_customer: 'cus_alice' },
    { id: 2, email: 'bob@x.com',   full_name: 'Bob',   stripe_customer: 'cus_bob' } ] },
  // 2. PERMISSIVE POLICY - policy exists but USING(true)
  posts:     { mode: 'permissive', rows: [
    { id: 1, owner: 1, title: 'draft', secret_notes: 'internal' } ] },
  // 3. PARTIAL COVERAGE - SELECT policy ok, but INSERT wide open
  comments:  { mode: 'partial_write', rows: [ { id: 1, owner: 1, body: 'hi' } ] },
  // 4. SERVICE_ROLE required (secure to anon) but table holds secrets
  api_keys:  { mode: 'secure', rows: [ { id: 1, owner: 1, key: 'sk_live_xxx' } ] },
  // 5. SECURE - proper RLS, anon gets nothing. The control.
  private_msgs: { mode: 'secure', rows: [ { id: 1, owner: 1, body: 'secret' }, { id: 2, owner: 2, body: 'bob msg' } ] },
  // 6. auth.uid() MISUSE - policy is USING(auth.uid() IS NOT NULL): any logged-in
  //    user sees ALL rows, not just their own. Invisible to anon (returns []).
  documents: { mode: 'authuid_misuse', rows: [
    { id: 1, owner: 1, content: 'alice doc' }, { id: 2, owner: 2, content: 'bob doc' } ] },
};

function rowsFor(table, key) {
  const t = TABLES[table];
  if (!t) return { status: 404, body: { message: `relation "${table}" does not exist` } };
  if (key === SERVICE) return { status: 200, body: t.rows };           // service_role bypasses RLS
  const uid = USERID[key];                                             // undefined for anon
  switch (t.mode) {
    case 'rls_off':      return { status: 200, body: t.rows };          // LEAK to everyone
    case 'permissive':   return { status: 200, body: t.rows };          // LEAK to everyone
    case 'partial_write':return { status: 200, body: t.rows.filter(r => r.owner === 0) };
    case 'secure':       // correct: owner-scoped for users, empty for anon
      return { status: 200, body: uid ? t.rows.filter(r => r.owner === uid) : [] };
    case 'authuid_misuse': // BUG: any logged-in user sees ALL rows; anon sees none
      return { status: 200, body: uid ? t.rows : [] };
    default:             return { status: 200, body: [] };
  }
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const key = (req.headers['apikey'] || (req.headers['authorization'] || '').replace('Bearer ', ''));
  res.setHeader('content-type', 'application/json');
  res.setHeader('server', 'postgrest/12.2.0');

  // table discovery via root OpenAPI
  if (url.pathname === '/rest/v1/' || url.pathname === '/rest/v1') {
    const paths = {}; for (const t of Object.keys(TABLES)) paths['/' + t] = {};
    return res.end(JSON.stringify({ swagger: '2.0', paths, definitions: Object.fromEntries(
      Object.keys(TABLES).map(t => [t, { properties: {} }])) }));
  }

  const m = url.pathname.match(/^\/rest\/v1\/([A-Za-z_][\w]*)$/);
  if (!m) { res.statusCode = 404; return res.end(JSON.stringify({ message: 'not found' })); }
  const table = m[1];

  if (req.method === 'GET') {
    const r = rowsFor(table, key);
    res.statusCode = r.status; return res.end(JSON.stringify(r.body));
  }
  if (req.method === 'POST') {
    const t = TABLES[table];
    if (!t) { res.statusCode = 404; return res.end(JSON.stringify({ message: 'no table' })); }
    // anon insert: allowed on rls_off + partial_write (the write hole), denied on secure/permissive-read-only
    const allowInsert = key === SERVICE || t.mode === 'rls_off' || t.mode === 'partial_write';
    if (allowInsert) { res.statusCode = 201; return res.end(JSON.stringify([{ id: 999, injected: true }])); }
    res.statusCode = 403; return res.end(JSON.stringify({ message: 'new row violates row-level security policy', code: '42501' }));
  }
  res.statusCode = 405; res.end(JSON.stringify({ message: 'method not allowed' }));
});

module.exports = { server, ANON, SERVICE, TABLES };
if (require.main === module) server.listen(54321, '127.0.0.1', () => console.log('supabase-mock on 54321'));
