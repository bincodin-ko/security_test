'use strict';
/**
 * VulnHunter verify phase: "a completely separate, read-only agent that
 * independently validates whether a finding was successfully remediated".
 *
 * Deliberately isolated: this module does not import invariants.js and never
 * sees how a finding was produced. It is handed only {inv, route, evidence}
 * and re-derives the attack from scratch. A fix is proven, not asserted.
 */
const VERIFIERS = {
  // re-run the cross-account read and demand a denial
  I1: async (ctx, f) => {
    const p = f.route.split(' ')[1];
    for (const id of ctx.probeIds) {
      const owner = await ctx.get(p.replace(/:\w+/, id), ctx.A.token);
      if (!(owner.status === 200 && owner.body)) continue;
      const other = await ctx.get(p.replace(/:\w+/, id), ctx.B.token);
      if (other.status === 200 && JSON.stringify(other.body) === JSON.stringify(owner.body))
        return { fixed: false, why: `other account still reads id=${id}` };
      return { fixed: true, why: `other account now gets ${other.status}` };
    }
    return { fixed: null, why: 'no readable resource found to test' };
  },
  I2: async (ctx, f) => {
    const p = f.route.split(' ')[1];
    const low  = await ctx.get(p, ctx.B.token);
    const high = await ctx.get(p, ctx.ADMIN.token);
    if (low.status === 200 && JSON.stringify(low.body) === JSON.stringify(high.body))
      return { fixed: false, why: 'regular user still receives the admin response' };
    return { fixed: true, why: `regular user now gets ${low.status}` };
  },
  I3: async (ctx, f) => {
    const p = f.route.split(' ')[1];
    const anon = await ctx.get(p, null);
    if (anon.status === 200 && anon.body && JSON.stringify(anon.body).length > 2)
      return { fixed: false, why: `anonymous request still returns ${anon.status} with a body` };
    return { fixed: true, why: `anonymous request now gets ${anon.status}` };
  },
  I6: async (ctx, f) => {
    const p = f.route.split(' ')[1];
    const res = await ctx.get(p, ctx.B.token);
    const leak = /password|hash|secret|token|api[_-]?key|db_password/i
      .test(JSON.stringify(res.body || {}));
    return leak ? { fixed: false, why: 'server-only field still present in response' }
                : { fixed: true, why: 'no server-only field in response' };
  },
  I4: async (ctx, f) => {
    if (!ctx.allowDestructive || !ctx.send) return { fixed: null, why: 'destructive verify disabled' };
    const p = f.route.split(' ')[1];
    const res = await ctx.send(`${f.route}`, ctx.B.token, { role: 'admin' });
    return (res.body && res.body.role === 'admin')
      ? { fixed: false, why: 'client can still set a privileged field' }
      : { fixed: true, why: 'server now ignores the privileged field' };
  },
  I5: async () => ({ fixed: null, why: 'state-transition legality is domain-specific; needs human confirmation' }),
};

async function verifyAll(ctx, findings) {
  const out = [];
  for (const f of findings) {
    const v = VERIFIERS[f.inv];
    if (!v) { out.push({ ...f, verification: { fixed: null, why: 'no independent verifier for this invariant' } }); continue; }
    out.push({ ...f, verification: await v(ctx, f) });
  }
  return out;
}
module.exports = { verifyAll };
