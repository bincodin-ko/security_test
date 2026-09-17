'use strict';
/**
 * I7 INJECTION — the same doctrine as I1–I6: suspect by inference, confirm by
 * execution. We do NOT static-match a payload list and call it a bug; we send a
 * probe and confirm only when an *oracle* fires:
 *
 *   SQLi (error-based)   a syntactically-breaking char makes the DB error,
 *                        while a benign value does not.
 *   SQLi (boolean-based) an always-true tautology returns strictly more rows
 *                        than a benign, non-matching value (the classic
 *                        LIKE '%%' OR '1'='1 result-set flip).
 *   Reflected XSS        a unique marker is echoed back inside an HTML response,
 *                        unescaped.
 *   Path traversal       a ../ payload returns the signature of a system file.
 *
 * Everything here is read-only (GET probes), so it is safe to run by default.
 */

const SQL_ERR = /(SQLITE_ERROR|SqliteError|syntax error|unrecognized token|near ".{0,3}":|unterminated|no such column|ORA-\d|MySQL|SQLSTATE|PG::|psql:|You have an error in your SQL)/i;
const PARAM_NAMES = ['q', 'query', 'search', 's', 'term', 'name', 'filter', 'category', 'sort', 'order'];
const XSS_MARK = 'xq9z7inj';
const TRAVERSAL = '../../../../../../etc/passwd';
const FILE_SIG = /root:.*:0:0:|\[extensions\]|; for 16-bit app support/;

async function get(base, path, token) {
  const headers = token ? { authorization: 'Bearer ' + token } : {};
  try {
    const r = await fetch(base + path, { headers });
    let text = '', body = null;
    try { text = await r.text(); body = JSON.parse(text); } catch {}
    return { status: r.status, text, body, headers: r.headers };
  } catch (e) { return { status: 0, text: String(e), body: null, headers: null }; }
}

const rowCount = (b) => (Array.isArray(b) ? b.length : b && typeof b === 'object' ? 1 : 0);
const looksTable = (b) => Array.isArray(b) && b.length > 0 && typeof b[0] === 'object';

async function I7_injection(ctx, route, out) {
  // Injection probing is read-only; still respect the destructive gate for
  // mutating verbs so we never send crafted bodies to writes unless allowed.
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(route.method) && !ctx.allowDestructive) return;
  const base = ctx.base, token = ctx.B.token;
  const hasPath = /:\w+/.test(route.path);

  // injection points: the path param (if any) + a wordlist of query params
  const points = [];
  if (hasPath) points.push({ kind: 'path' });
  for (const n of PARAM_NAMES) points.push({ kind: 'query', name: n });

  const mk = (pt, val) => pt.kind === 'path'
    ? route.path.replace(/:\w+/, encodeURIComponent(val))
    : `${route.path}?${pt.name}=${encodeURIComponent(val)}`;

  for (const pt of points) {
    const where = pt.kind === 'path' ? '(path param)' : `?${pt.name}`;

    // ── SQLi, error-based ──────────────────────────────────────────────────
    const broke = await get(base, mk(pt, "'"), token);
    if (broke.status >= 500 && SQL_ERR.test(broke.text)) {
      const benign = await get(base, mk(pt, 'abc'), token);         // control
      if (benign.status < 500) {
        out.push({ inv: 'I7', route: `${route.method} ${route.path}`, verdict: 'confirmed',
          title: 'SQL injection: input is concatenated into the query',
          evidence: `${where}: "'" → ${broke.status} with a DB error (${broke.text.replace(/\s+/g, ' ').slice(0, 70)}…), while "abc" → ${benign.status}` });
        return;
      }
    }

    // ── SQLi, boolean-based (result-set flip) ──────────────────────────────
    if (pt.kind === 'query') {
      const none = await get(base, mk(pt, 'zzq_nomatch_7q9'), token);
      const all = await get(base, mk(pt, "%' OR '1'='1"), token);
      if (all.status === 200 && looksTable(all.body) && rowCount(all.body) > rowCount(none.body)) {
        out.push({ inv: 'I7', route: `${route.method} ${route.path}`, verdict: 'confirmed',
          title: 'SQL injection: a tautology changed the result set',
          evidence: `${where}: benign → ${rowCount(none.body)} row(s), "' OR '1'='1" → ${rowCount(all.body)} row(s) (whole table)` });
        return;
      }
    }
  }

  // ── Reflected XSS ─────────────────────────────────────────────────────────
  for (const n of ['q', 'query', 'search', 'name', 's']) {
    const r = await get(base, `${route.path}?${n}=${encodeURIComponent(`"><${XSS_MARK}>`)}`, token);
    const ct = (r.headers && r.headers.get && r.headers.get('content-type')) || '';
    if (/text\/html/i.test(ct) && r.text.includes(`<${XSS_MARK}>`)) {
      out.push({ inv: 'I7', route: `${route.method} ${route.path}`, verdict: 'confirmed',
        title: 'Reflected XSS: input echoed into HTML unescaped',
        evidence: `?${n} reflected the marker <${XSS_MARK}> unescaped in an HTML response` });
      return;
    }
  }

  // ── Path traversal ─────────────────────────────────────────────────────────
  if (hasPath) {
    const r = await get(base, route.path.replace(/:\w+/, encodeURIComponent(TRAVERSAL)), token);
    if (r.status === 200 && FILE_SIG.test(r.text)) {
      out.push({ inv: 'I7', route: `${route.method} ${route.path}`, verdict: 'confirmed',
        title: 'Path traversal: a ../ payload reached a system file',
        evidence: `path param "${TRAVERSAL}" returned a system-file signature` });
      return;
    }
  }
}

// Independent disprover for the adversary stage: re-derive the attack from
// scratch and try to falsify it. Only survivors stay confirmed.
async function disproveI7(ctx, f) {
  const base = ctx.base, token = ctx.B.token;
  const path = f.route.split(' ').slice(1).join(' ');
  const q = (v) => `${path}${path.includes('?') ? '&' : '?'}q=${encodeURIComponent(v)}`;
  const broke = await get(base, q("'"), token);
  if (broke.status >= 500 && SQL_ERR.test(broke.text)) {
    const benign = await get(base, q('abc'), token);
    if (benign.status < 500) return { survives: true, why: 're-issued "\'" reproduces a DB error; benign value does not', evidence: broke.text.replace(/\s+/g, ' ').slice(0, 60) };
  }
  const none = await get(base, q('zzq_nomatch_7q9'), token);
  const all = await get(base, q("%' OR '1'='1"), token);
  if (all.status === 200 && looksTable(all.body) && rowCount(all.body) > rowCount(none.body))
    return { survives: true, why: 'tautology still returns more rows than a benign value', evidence: `${rowCount(none.body)} → ${rowCount(all.body)} rows` };
  return { survives: false, why: 'injection oracle did not reproduce on re-check' };
}

module.exports = { I7_injection, disproveI7 };
