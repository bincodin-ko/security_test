'use strict';
/**
 * Six invariants. Note what is NOT here: any list of vulnerability names.
 * These rules are applied to every discovered route, including routes that
 * did not exist when this file was written.
 *
 * Verdicts follow Cloudflare's 3-way scheme:
 *   confirmed        - observed a boundary failure, with evidence
 *   needs_validation - suspicious, but an exact fact is unresolved
 *   rejected         - probed and the boundary held
 */

const PRIVILEGED_FIELDS = ['role', 'isAdmin', 'is_admin', 'admin', 'plan', 'credits',
                           'balance', 'price', 'amount', 'verified', 'owner_id', 'user_id'];
const SECRET_HINTS = /(password|passwd|hash|secret|token|api[_-]?key|private[_-]?key|FIXTURE-PAYMENT)/i;
const SECRET_VALUE = /^(?:[a-f0-9]{32,}|[A-Za-z0-9_\-]{32,})$/;

const req = async (base, route, { token, pathParams = {}, body, query } = {}) => {
  let p = route.path.replace(/:([A-Za-z_]\w*)/g, (_, n) => pathParams[n] ?? '1');
  if (query) p += '?' + new URLSearchParams(query);
  const headers = { 'content-type': 'application/json' };
  if (token) headers.authorization = 'Bearer ' + token;
  try {
    const r = await fetch(base + p, {
      method: route.method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
    let parsed = null, text = '';
    try { text = await r.text(); parsed = JSON.parse(text); } catch {}
    return { status: r.status, body: parsed, text, path: p, headers: r.headers };
  } catch (e) { return { status: 0, body: null, text: String(e), path: p }; }
};

const isMutating = r => ['POST', 'PUT', 'PATCH', 'DELETE'].includes(r.method);
const hasParam   = r => /:\w+/.test(r.path);
const looksLikeData = res =>
  res.status === 200 && res.body && JSON.stringify(res.body).length > 2;

/* ── I1 ISOLATION ─────────────────────────────────────────────────────────
   A's data must never appear in a response to B's token.                   */
async function I1_isolation(ctx, route, out) {
  if (!hasParam(route)) return;
  if (isMutating(route) && !ctx.allowDestructive) {
    return out.push({ inv: 'I1', route: `${route.method} ${route.path}`,
      verdict: 'needs_validation', title: 'Mutating route with id param not tested',
      unresolved: 'destructive test disabled; cannot confirm ownership enforcement' });
  }
  // find an id the owner (A) can read, then ask for it as B
  for (const id of ctx.probeIds) {
    const asA = await req(ctx.base, { ...route, method: 'GET' }, { token: ctx.A.token, pathParams: { id } });
    if (!looksLikeData(asA)) continue;
    const asB = await req(ctx.base, { ...route, method: 'GET' }, { token: ctx.B.token, pathParams: { id } });
    if (asB.status === 200 && JSON.stringify(asB.body) === JSON.stringify(asA.body)) {
      return out.push({ inv: 'I1', route: `${route.method} ${route.path}`,
        verdict: 'confirmed', title: 'Cross-account read: isolation broken',
        evidence: `${ctx.B.email} received ${ctx.A.email}'s resource id=${id} verbatim: ` +
                  JSON.stringify(asB.body).slice(0, 90) });
    }
    if (asB.status === 403 || asB.status === 404) {
      return out.push({ inv: 'I1', route: `${route.method} ${route.path}`,
        verdict: 'rejected', title: 'Isolation holds',
        evidence: `owner got 200, other account got ${asB.status}` });
    }
  }
}

/* ── I2 PRIVILEGE MONOTONICITY ────────────────────────────────────────────
   A low-privilege token must not obtain a high-privilege result.
   Identical responses alone prove nothing - a public endpoint looks the same
   to everyone. Confirm only with positive evidence of privilege: the payload
   carries records the requester does not own, or fields only an operator
   should see.                                                              */
const ADMIN_PATH = /admin|internal|manage|ops|backoffice|owner|superuser/i;

// Does this payload contain records belonging to someone other than `self`?
function foreignRecords(body, selfId) {
  const rows = Array.isArray(body) ? body : [body];
  let foreign = 0;
  for (const r of rows) {
    if (!r || typeof r !== 'object') continue;
    const owner = r.owner_id ?? r.user_id ?? r.userId ?? r.ownerId ?? (r.id !== undefined && r.email ? r.id : undefined);
    if (owner !== undefined && String(owner) !== String(selfId)) foreign++;
  }
  return foreign;
}

async function I2_privilege(ctx, route, out) {
  if (isMutating(route) && !ctx.allowDestructive) return;
  const asLow  = await req(ctx.base, route, { token: ctx.B.token });
  const asHigh = await req(ctx.base, route, { token: ctx.ADMIN.token });
  if (!looksLikeData(asHigh) || asLow.status !== 200) return;
  if (JSON.stringify(asLow.body) !== JSON.stringify(asHigh.body)) return;

  const foreign = foreignRecords(asLow.body, ctx.B.id);
  const operatorFields = SECRET_HINTS.test(JSON.stringify(asLow.body));
  const adminScoped = ADMIN_PATH.test(route.path);

  if (foreign > 0 || operatorFields) {
    return out.push({ inv: 'I2', route: `${route.method} ${route.path}`,
      verdict: 'confirmed', title: 'Privilege escalation: operator-scope data reachable by a regular user',
      evidence: `identical to admin response; ${foreign} record(s) not owned by requester` +
                (operatorFields ? ', payload carries operator-only fields' : '') });
  }
  if (adminScoped) {
    return out.push({ inv: 'I2', route: `${route.method} ${route.path}`,
      verdict: 'needs_validation', title: 'Admin-named route answers a regular user',
      unresolved: 'path suggests operator scope but payload shows no ownership markers' });
  }
  out.push({ inv: 'I2', route: `${route.method} ${route.path}`,
    verdict: 'rejected', title: 'Same response for all roles, but no privileged content',
    evidence: 'looks like a genuinely public endpoint' });
}

/* ── I3 ANONYMOUS DENIAL ──────────────────────────────────────────────────
   No token must mean no user data.                                         */
async function I3_anonymous(ctx, route, out) {
  if (isMutating(route) && !ctx.allowDestructive) return;
  const anon = await req(ctx.base, route, {});
  if (!looksLikeData(anon)) return;
  const s = JSON.stringify(anon.body);
  const pii = /[\w.+-]+@[\w-]+\.\w+/.test(s) || SECRET_HINTS.test(s);
  out.push({ inv: 'I3', route: `${route.method} ${route.path}`,
    verdict: pii ? 'confirmed' : 'needs_validation',
    title: pii ? 'Unauthenticated access returns user data'
               : 'Unauthenticated access returns a payload',
    evidence: s.slice(0, 90),
    unresolved: pii ? undefined : 'cannot tell whether this payload is meant to be public' });
}

/* ── I4 INPUT DISTRUST ────────────────────────────────────────────────────
   A client-supplied value must not decide privilege or money.              */
async function I4_input(ctx, route, out) {
  if (!['POST', 'PUT', 'PATCH'].includes(route.method)) return;
  if (!ctx.allowDestructive) {
    return out.push({ inv: 'I4', route: `${route.method} ${route.path}`,
      verdict: 'needs_validation', title: 'Write route not probed for mass assignment',
      unresolved: 'destructive test disabled' });
  }
  for (const field of PRIVILEGED_FIELDS) {
    const payload = { [field]: field === 'role' ? 'admin' : 999999 };
    const res = await req(ctx.base, route, { token: ctx.B.token, body: payload });
    if (res.status < 300 && res.body && String(res.body[field]) === String(payload[field])) {
      return out.push({ inv: 'I4', route: `${route.method} ${route.path}`,
        verdict: 'confirmed', title: 'Mass assignment: client set a privileged field',
        evidence: `sent {"${field}":${JSON.stringify(payload[field])}} -> server echoed ${field}=${res.body[field]}` });
    }
  }
}

/* ── I5 STATE DIRECTIONALITY ──────────────────────────────────────────────
   Money/permission state must not move backwards. Needs domain knowledge,
   so this invariant only ever raises a question.                           */
async function I5_state(ctx, route, out) {
  if (!isMutating(route)) return;
  if (PRIVILEGED_FIELDS.some(f => route.path.includes(f)) ||
      /order|payment|subscription|invoice|refund|status/i.test(route.path)) {
    out.push({ inv: 'I5', route: `${route.method} ${route.path}`,
      verdict: 'needs_validation', title: 'State-changing route on a money/permission object',
      unresolved: 'only the app owner knows which transitions are legal' });
  }
}

/* ── I6 SECRET NON-EXPOSURE ───────────────────────────────────────────────
   Server-only values must never reach a client.                            */
async function I6_secrets(ctx, route, out) {
  if (isMutating(route) && !ctx.allowDestructive) return;
  for (const who of [null, ctx.B.token]) {
    const res = await req(ctx.base, route, { token: who });
    if (!res.body) continue;
    const hits = [];
    (function walk(o, p = '') {
      if (o && typeof o === 'object')
        for (const [k, v] of Object.entries(o)) walk(v, p ? `${p}.${k}` : k);
      else if (typeof o === 'string' &&
               (SECRET_HINTS.test(p) || (SECRET_VALUE.test(o) && SECRET_HINTS.test(p))))
        hits.push(`${p}=${String(o).slice(0, 24)}`);
    })(res.body);
    if (hits.length) {
      return out.push({ inv: 'I6', route: `${route.method} ${route.path}`,
        verdict: 'confirmed', title: 'Server-only value returned to client',
        evidence: hits.slice(0, 3).join(', ') + (who ? ' (authenticated)' : ' (ANONYMOUS)') });
    }
  }
}

const { I7_injection } = require('./injection');
const ALL = [I1_isolation, I2_privilege, I3_anonymous, I4_input, I5_state, I6_secrets, I7_injection];
module.exports = { ALL, req };
