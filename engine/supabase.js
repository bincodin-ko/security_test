'use strict';
const { Sandbox } = require('./sandbox');
/**
 * Supabase / BaaS adapter. Real-world #1 cause of vibe-coded breaches:
 * missing or broken Row Level Security. 83% of Supabase exposures.
 *
 * Input: the app's PUBLIC anon key (the same one shipped in the frontend
 * bundle - not a secret) and the project URL. We never need service_role.
 *
 * We reuse the invariant idea: instead of reading policy files (which don't
 * exist in the repo - they're server state), we OBSERVE what the anon key can
 * do. Five failure modes, each proven by an actual request.
 */

async function req(base, table, { key, method = 'GET', body } = {}) {
  const url = `${base}/rest/v1/${table}` + (method === 'GET' ? '?select=*' : '');
  const headers = { apikey: key, authorization: 'Bearer ' + key, 'content-type': 'application/json' };
  if (method === 'POST') headers.prefer = 'return=representation';
  try {
    const r = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined });
    let b = null; try { b = await r.json(); } catch {}
    return { status: r.status, body: b };
  } catch (e) { return { status: 0, body: null, err: String(e) }; }
}

// Table discovery via PostgREST's OpenAPI root - no guessing.
async function discoverTables(base, key) {
  const r = await req(base, '', { key });
  // root returns spec; fetch it directly
  try {
    const res = await fetch(`${base}/rest/v1/`, { headers: { apikey: key, authorization: 'Bearer ' + key } });
    const spec = await res.json();
    if (spec && spec.paths) return Object.keys(spec.paths).map(p => p.replace(/^\//, '')).filter(Boolean);
  } catch {}
  return [];
}

const SECRET_COL = /(email|phone|ssn|password|hash|secret|token|key|stripe|card|api[_-]?key|address|birth)/i;

function looksSensitive(rows) {
  if (!Array.isArray(rows) || !rows.length) return false;
  return Object.keys(rows[0] || {}).some(c => SECRET_COL.test(c));
}

async function audit({ base, anonKey, probeWrite = false }) {
  const tables = await discoverTables(base, anonKey);
  const findings = [];
  const add = (f) => findings.push({ ...f, evidence: Sandbox.redact(f.evidence) });

  for (const table of tables) {
    // MODE 1+2: RLS off / permissive - anon can READ rows
    const read = await req(base, table, { key: anonKey });
    if (read.status === 200 && Array.isArray(read.body) && read.body.length > 0) {
      const sensitive = looksSensitive(read.body);
      add({
        table, mode: sensitive ? 'rls_off_sensitive' : 'rls_off',
        verdict: 'confirmed',
        severity: sensitive ? 5 : 4,
        title: sensitive
          ? `Anon key reads sensitive rows from "${table}" (RLS off or permissive)`
          : `Anon key reads all rows from "${table}" (RLS off or permissive)`,
        evidence: `GET with public anon key returned ${read.body.length} row(s): ` +
          JSON.stringify(read.body[0]).slice(0, 90),
        fix: `Enable RLS on "${table}" and add a policy scoping rows to auth.uid(). ` +
             `ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY; then a USING (owner = auth.uid()) policy.`,
      });
    }

    // Locked but high-value: secure to anon, yet holds secrets. If service_role
    // ever leaks (frontend bundle, env misconfig) this table is the crown jewel.
    if (read.status === 200 && Array.isArray(read.body) && read.body.length === 0) {
      // can't see columns when RLS returns empty; flag by table name heuristic
      if (/key|secret|token|credential|payment|card/i.test(table)) {
        add({ table, mode: 'high_value_locked', verdict: 'needs_validation', severity: 2,
          title: `"${table}" is locked to anon but likely holds secrets`,
          evidence: `anon read returned empty (RLS active) - good, but this is a service_role-leak crown jewel`,
          fix: `Confirm service_role key never reaches the client, and consider moving secrets to a vault table with column-level restrictions.` });
      }
    }

    // MODE 3: partial coverage - READ locked but WRITE open
    if (probeWrite) {
      const ins = await req(base, table, { key: anonKey, method: 'POST', body: { probe: 'scanner-test' } });
      if (ins.status === 201) {
        add({
          table, mode: 'partial_write', verdict: 'confirmed', severity: 5,
          title: `Anon key can INSERT into "${table}" (write policy missing)`,
          evidence: `POST with public anon key returned 201 Created`,
          fix: `Add INSERT/UPDATE/DELETE policies too. A SELECT-only policy leaves writes open. ` +
               `Every command (SELECT, INSERT, UPDATE, DELETE) needs its own policy.`,
        });
      }
    }
  }

  // Coverage summary for the ledger
  return {
    tablesFound: tables.length,
    tables,
    findings,
    secure: tables.filter(t => !findings.some(f => f.table === t)),
  };
}

module.exports = { audit, discoverTables, req };
