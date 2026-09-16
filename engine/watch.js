'use strict';
/**
 * Aikido sells "continuous", and its free tier rescans every 3 days. The gap
 * that matters is the window between a deploy and the next scan.
 *
 * Cheap trigger: surface diff. New code is the only source of new
 * vulnerabilities, so hash the route inventory and run the full sweep only
 * when it changes. Everything here is LLM-free.
 */
const crypto = require('crypto');
const fs = require('fs');

const surfaceHash = routes => crypto.createHash('sha1')
  .update(routes.map(r => `${r.method} ${r.path}`).sort().join('\n')).digest('hex');

function diffSurface(stateFile, routes) {
  let prev = { hash: null, routes: [] };
  try { prev = JSON.parse(fs.readFileSync(stateFile, 'utf8')); } catch {}
  const now = routes.map(r => `${r.method} ${r.path}`).sort();
  const hash = surfaceHash(routes);
  const added   = now.filter(r => !prev.routes.includes(r));
  const removed = (prev.routes || []).filter(r => !now.includes(r));
  fs.writeFileSync(stateFile, JSON.stringify({ hash, routes: now, at: new Date().toISOString() }, null, 2));
  return { changed: prev.hash !== hash, first: !prev.hash, added, removed, hash };
}

/** What a scheduler would decide to run, and why. */
function plan({ trigger, surface, hoursSinceFull }) {
  if (trigger === 'deploy' && surface.added.length)
    return { scope: 'new-surface', routes: surface.added, cost: 'low',
             why: `${surface.added.length} new endpoint(s) since last scan` };
  if (trigger === 'deploy')
    return { scope: 'none', cost: 'none', why: 'deploy did not change the route surface' };
  if (hoursSinceFull >= 24)
    return { scope: 'full-readonly', cost: 'low', why: 'daily read-only sweep' };
  if (trigger === 'weekly')
    return { scope: 'full-destructive', cost: 'high',
             why: 'weekly deep pass incl. write/delete probes' };
  return { scope: 'none', cost: 'none', why: 'nothing due' };
}
module.exports = { diffSurface, plan, surfaceHash };
