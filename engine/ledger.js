'use strict';
/**
 * Cloudflare: coverage-ledger + "multiple runs are additive".
 * A single run finds roughly half of what repeated runs find, so runs must
 * accumulate: remember what was checked, carry forward evidence, and report
 * what changed since last time.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const key = f => `${f.inv}|${f.route}`;
const fingerprint = f => crypto.createHash('sha1')
  .update(`${f.inv}|${f.route}|${f.title}`).digest('hex').slice(0, 12);

function load(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return { runs: 0, firstSeen: {}, units: {}, history: [] }; }
}

function save(file, l) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(l, null, 2));
}

/**
 * Merge a run into the ledger and return what changed.
 * A finding that disappears is NOT silently dropped - it becomes `fixed`
 * only if this run actually covered that unit, otherwise `stale`.
 */
function record(ledgerFile, run) {
  const l = load(ledgerFile);
  const now = new Date().toISOString();
  l.runs += 1;

  const covered = new Set(run.coveredUnits);            // "METHOD path" checked this run
  const current = new Map(run.confirmed.map(f => [key(f), f]));
  const previous = new Map(Object.entries(l.units)
    .filter(([, u]) => u.state === 'open').map(([k, u]) => [k, u]));

  const isNew = [], persisting = [], fixed = [], stale = [];

  for (const [k, f] of current) {
    const seen = l.units[k];
    if (!seen || seen.state !== 'open') {
      l.firstSeen[k] = l.firstSeen[k] || now;
      isNew.push(f);
    } else persisting.push(f);
    l.units[k] = { state: 'open', inv: f.inv, route: f.route, title: f.title,
                   fingerprint: fingerprint(f), firstSeen: l.firstSeen[k], lastSeen: now };
  }

  for (const [k, u] of previous) {
    if (current.has(k)) continue;
    const routeOnly = u.route;
    if (covered.has(routeOnly)) {
      l.units[k] = { ...u, state: 'fixed', fixedAt: now };
      fixed.push(u);
    } else {
      l.units[k] = { ...u, state: 'open', note: 'not covered this run' };
      stale.push(u);
    }
  }

  l.history.push({ at: now, run: l.runs, routes: run.coveredUnits.length,
                   confirmed: run.confirmed.length, new: isNew.length,
                   fixed: fixed.length });
  if (l.history.length > 200) l.history = l.history.slice(-200);
  save(ledgerFile, l);

  const cumulative = Object.values(l.units).filter(u => u.state === 'open').length;
  return { isNew, persisting, fixed, stale, run: l.runs, cumulative };
}

/** Which routes has the ledger never checked? (coverage gaps) */
function gaps(ledgerFile, routes) {
  const l = load(ledgerFile);
  const everChecked = new Set(Object.values(l.units).map(u => u.route));
  return routes.map(r => `${r.method} ${r.path}`).filter(u => !everChecked.has(u));
}

module.exports = { record, load, gaps, fingerprint };
