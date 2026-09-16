'use strict';
/**
 * Aikido AutoTriage: dedupe across scanners, correlate related findings,
 * drop non-exploitable noise. The goal is one row per root cause, not one row
 * per rule that noticed it.
 *
 * Our own scan proved the need: 13 confirmed -> 6 were duplicates of the same
 * endpoint (46% noise). A vibe-coder who sees the same route three times stops
 * reading.
 */

// Severity model: likelihood x impact, per Cloudflare "severity requires impact".
const IMPACT = { I1: 5, I2: 5, I3: 4, I4: 5, I5: 3, I6: 4 };
const ANON_BONUS = 1; // reachable with no credentials = worse

function severity(f) {
  let s = IMPACT[f.inv] || 2;
  if (/ANONYMOUS/i.test(f.evidence || '')) s = Math.min(5, s + ANON_BONUS);
  return s; // 1..5
}

// A single code defect often trips several invariants on one route.
// Group by route, keep the highest-impact finding as primary, fold the rest in.
function cluster(confirmed) {
  const groups = new Map();
  for (const f of confirmed) {
    const g = groups.get(f.route) || [];
    g.push({ ...f, severity: severity(f) });
    groups.set(f.route, g);
  }
  const clustered = [];
  for (const [route, fs] of groups) {
    fs.sort((a, b) => b.severity - a.severity);
    const primary = fs[0];
    const also = fs.slice(1);
    // Root-cause hint: multiple invariants on one route usually share a cause.
    const cause = inferCause(fs.map(f => f.inv));
    clustered.push({
      route,
      severity: primary.severity,
      primary: primary.title,
      invariants: fs.map(f => f.inv),
      rootCause: cause,
      evidence: primary.evidence,
      alsoViolates: also.map(f => `${f.inv}: ${f.title}`),
      count: fs.length,
    });
  }
  clustered.sort((a, b) => b.severity - a.severity || b.count - a.count);
  return clustered;
}

// Heuristic: which single fix collapses this cluster?
function inferCause(invs) {
  const set = new Set(invs);
  if (set.has('I3') && set.has('I6')) return 'route is reachable without auth AND leaks server-only fields — add auth middleware and stop selecting secret columns';
  if (set.has('I1') && set.has('I2')) return 'no ownership check on this route — one owner_id comparison fixes both the cross-account read and the privilege finding';
  if (set.has('I3')) return 'missing authentication on this route';
  if (set.has('I6')) return 'response serialises a server-only field';
  if (set.has('I4')) return 'server trusts a client-supplied privileged field';
  return 'see individual findings';
}

/**
 * Reachability gate (VulnHunter capability filter, generalised):
 * a finding only survives if it was actually reached. We already only emit
 * `confirmed` on observation, so here we drop anything whose evidence does not
 * demonstrate reach, and demote defense-in-depth notes.
 */
function reachable(f) {
  // confirmed findings carry observed evidence; needs_validation do not.
  return f.verdict === 'confirmed' && !!f.evidence;
}

function triage(findings) {
  const confirmed = findings.filter(reachable);
  const clusters = cluster(confirmed);
  const suppressed = findings.length - confirmed.length;
  return {
    clusters,
    rows: clusters.length,
    rawConfirmed: confirmed.length,
    dedupeRatio: confirmed.length ? +(1 - clusters.length / confirmed.length).toFixed(2) : 0,
    suppressed,
  };
}
module.exports = { triage, cluster, severity };
