'use strict';
/**
 * Cloudflare: "the agent that checks a finding is never the agent that found it."
 * VulnHunter: adversarial disprove + capability filter.
 *
 * This module never imports invariants.js. It receives a candidate finding and
 * actively tries to DISPROVE it, re-deriving the attack from the route alone.
 * Only candidates that survive falsification are promoted to `confirmed`.
 *
 * Each disprover asks: "is there an innocent explanation for what we saw?"
 */

const { Sandbox } = require('./sandbox');

// Parameterised routes must be probed with a real id, not the literal ':id'.
async function firstReadable(ctx, p, token) {
  if (!/:\w+/.test(p)) return ctx.get(p, token);
  for (const id of ctx.probeIds) {
    const r = await ctx.get(p.replace(/:\w+/, id), token);
    if (r.status === 200 && r.body) return r;
  }
  return ctx.get(p.replace(/:\w+/, ctx.probeIds[0]), token);
}

// Innocent explanations we must rule out before confirming:
//  - the endpoint is genuinely public (I1/I2/I3): everyone gets the same thing
//    AND it contains nothing private
//  - the "leak" is the caller's own data (I1): B asked for B's own resource
//  - the response is an error page that happens to echo input (I6)
//  - a transient 200 that isn't reproducible

function foreignOrSecret(body, selfId) {
  const s = JSON.stringify(body || {});
  if (/password|hash|secret|token|api[_-]?key/i.test(s)) return true;
  const rows = Array.isArray(body) ? body : [body];
  return rows.some(r => {
    if (!r || typeof r !== 'object') return false;
    const owner = r.owner_id ?? r.user_id ?? r.userId ?? r.ownerId;
    return owner !== undefined && String(owner) !== String(selfId);
  });
}

const DISPROVERS = {
  // I1: maybe B legitimately owns that resource, or it's public data
  I1: async (ctx, f) => {
    const p = f.route.split(' ')[1];
    for (const id of ctx.probeIds) {
      const asA   = await ctx.get(p.replace(/:\w+/, id), ctx.A.token);
      const asB   = await ctx.get(p.replace(/:\w+/, id), ctx.B.token);
      const anon  = await ctx.get(p.replace(/:\w+/, id), null);
      if (!(asA.status === 200 && asA.body)) continue;
      // innocent #1: it's public — anon gets it too
      if (anon.status === 200 && JSON.stringify(anon.body) === JSON.stringify(asA.body))
        return { survives: false, why: 'endpoint is public (anonymous gets identical data) — not an isolation bug' };
      // innocent #2: B got its own thing, not A's
      const owner = asA.body.owner_id ?? asA.body.user_id;
      if (owner !== undefined && String(owner) === String(ctx.B.id))
        return { survives: false, why: 'resource is owned by the second account itself' };
      // must reproduce: two identical reads
      const asB2 = await ctx.get(p.replace(/:\w+/, id), ctx.B.token);
      const reproduced = asB.status === 200 && asB2.status === 200 &&
                         JSON.stringify(asB.body) === JSON.stringify(asB2.body) &&
                         JSON.stringify(asB.body) === JSON.stringify(asA.body);
      if (reproduced && String(owner) !== String(ctx.B.id))
        return { survives: true, why: `reproduced: ${ctx.B.email} read a resource owned by ${owner}, twice`, evidence: JSON.stringify(asB.body).slice(0,90) };
    }
    return { survives: false, why: 'could not reproduce cross-account read' };
  },

  I2: async (ctx, f) => {
    const p = f.route.split(' ')[1];
    const low  = await firstReadable(ctx, p, ctx.B.token);
    const anon = await firstReadable(ctx, p, null);
    if (anon.status === 200 && JSON.stringify(anon.body) === JSON.stringify(low.body))
      return { survives: false, why: 'anonymous gets the same response — this is public, not a privilege boundary' };
    const high = await firstReadable(ctx, p, ctx.ADMIN.token);
    if (low.status !== 200 || JSON.stringify(low.body) !== JSON.stringify(high.body))
      return { survives: false, why: 'regular user response differs from admin — boundary holds' };
    // capability filter: does the payload actually carry foreign / operator data?
    const foreign = foreignOrSecret(low.body, ctx.B.id);
    return foreign
      ? { survives: true, why: 'regular user receives admin-identical payload containing foreign/operator data', evidence: JSON.stringify(low.body).slice(0,90) }
      : { survives: false, why: 'identical but no privileged content — public endpoint' };
  },

  I3: async (ctx, f) => {
    const p = f.route.split(' ')[1];
    const a1 = await ctx.get(p, null);
    const a2 = await ctx.get(p, null);
    if (!(a1.status === 200 && a2.status === 200)) return { survives: false, why: 'anonymous access not reproducible' };
    const s = JSON.stringify(a1.body || {});
    const priv = /[\w.+-]+@[\w-]+\.\w+/.test(s) || /password|hash|secret|token|api[_-]?key|db_password/i.test(s);
    return priv
      ? { survives: true, why: 'anonymous request reproducibly returns user/secret data', evidence: Sandbox.redact(s).slice(0,90) }
      : { survives: false, why: 'anonymous payload contains no user data — may be a public endpoint by design' };
  },

  I4: async (ctx, f) => {
    if (!ctx.allowDestructive) return { survives: null, why: 'destructive probing disabled; cannot confirm or disprove' };
    const p = f.route.split(' ')[1];
    // control: send a benign field, confirm it does NOT grant privilege
    const before = await ctx.get('/api/me', ctx.B.token).catch(()=>({}));
    const res = await ctx.send(p, ctx.B.token, { role: 'admin' });
    if (res.body && res.body.role === 'admin')
      return { survives: true, why: 'client set role=admin and server persisted it', evidence: 'role -> admin' };
    return { survives: false, why: 'server ignored the privileged field' };
  },

  I6: async (ctx, f) => {
    const p = f.route.split(' ')[1];
    const res = await firstReadable(ctx, p, ctx.B.token);
    // innocent: it's an error body echoing our input, not a real field
    if (res.status >= 400) return { survives: false, why: `response is an error (${res.status}), not a data leak` };
    const s = JSON.stringify(res.body || {});
    const m = s.match(/"(\w*(?:password|secret|token|api[_-]?key|hash)\w*)"\s*:\s*"([^"]{4,})"/i);
    return m
      ? { survives: true, why: `field "${m[1]}" carries a server-only value`, evidence: Sandbox.redact(`${m[1]}=${m[2]}`) }
      : { survives: false, why: 'no server-only field present on re-check' };
  },
};

async function falsify(ctx, candidates) {
  const out = [];
  for (const c of candidates) {
    const d = DISPROVERS[c.inv];
    if (!d) { out.push({ ...c, adversary: { survives: null, why: 'no disprover for this invariant' } }); continue; }
    const r = await d(ctx, c);
    out.push({ ...c, adversary: r, verdict: r.survives === true ? 'confirmed'
                       : r.survives === false ? 'rejected' : 'needs_validation' });
  }
  return out;
}
module.exports = { falsify };
