'use strict';
/**
 * SCA — Software Composition Analysis. Reads the project's lockfiles, then asks
 * OSV.dev (the same free vulnerability database osv-scanner / GitHub use) which
 * of those exact versions have known CVEs.
 *
 * This is deterministic and needs no model: parse lockfile → {ecosystem, name,
 * version} → OSV batch query → report. It requires the repository (a lockfile)
 * and outbound access to api.osv.dev.
 */
const fs = require('fs');
const path = require('path');

// ── lockfile parsers → [{ ecosystem, name, version }] ──────────────────────
function fromNpmLock(file) {
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  const out = [];
  if (j.packages) { // lockfile v2/v3
    for (const [p, meta] of Object.entries(j.packages)) {
      if (!p || !meta.version) continue;
      const name = p.startsWith('node_modules/') ? p.slice(p.lastIndexOf('node_modules/') + 13) : (meta.name || null);
      if (name) out.push({ ecosystem: 'npm', name, version: meta.version });
    }
  } else if (j.dependencies) { // v1
    (function walk(deps) { for (const [name, m] of Object.entries(deps)) { if (m.version) out.push({ ecosystem: 'npm', name, version: m.version }); if (m.dependencies) walk(m.dependencies); } })(j.dependencies);
  }
  return out;
}
function fromPnpmLock(file) {
  const txt = fs.readFileSync(file, 'utf8'), out = [];
  // packages: entries like  /name@1.2.3:  or  /@scope/name@1.2.3:
  const re = /^\s{2}\/?((?:@[\w.-]+\/)?[\w.-]+)@([\d][\w.\-+]*):/gm;
  let m; while ((m = re.exec(txt))) out.push({ ecosystem: 'npm', name: m[1], version: m[2] });
  return out;
}
function fromRequirements(file) {
  return fs.readFileSync(file, 'utf8').split('\n').map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#') && l.includes('=='))
    .map((l) => { const [name, version] = l.split('==').map((s) => s.trim()); return { ecosystem: 'PyPI', name, version }; });
}

function collect(dir) {
  const tries = [
    ['package-lock.json', fromNpmLock], ['npm-shrinkwrap.json', fromNpmLock],
    ['pnpm-lock.yaml', fromPnpmLock], ['requirements.txt', fromRequirements],
  ];
  for (const [f, parse] of tries) {
    const p = path.join(dir, f);
    if (fs.existsSync(p)) { try { const deps = parse(p); if (deps.length) return { lockfile: f, deps: dedupe(deps) }; } catch {} }
  }
  return { lockfile: null, deps: [] };
}
const dedupe = (deps) => { const s = new Map(); for (const d of deps) s.set(`${d.ecosystem}:${d.name}@${d.version}`, d); return [...s.values()]; };

// ── OSV.dev batch query ─────────────────────────────────────────────────────
async function queryOSV(deps) {
  const body = { queries: deps.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })) };
  const r = await fetch('https://api.osv.dev/v1/querybatch', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`OSV ${r.status}`);
  const j = await r.json();
  const findings = [];
  (j.results || []).forEach((res, i) => {
    if (res.vulns && res.vulns.length) findings.push({ ...deps[i], vulns: res.vulns.map((v) => v.id) });
  });
  return findings;
}

async function audit(dir) {
  const { lockfile, deps } = collect(dir);
  if (!lockfile) return { lockfile: null, deps: 0, findings: [], note: 'no lockfile found' };
  let findings = [], note = null;
  try { findings = await queryOSV(deps); }
  catch (e) { note = `OSV unreachable (${e.message}) — parsed ${deps.length} deps but could not query`; }
  return { lockfile, deps: deps.length, findings, note };
}

module.exports = { audit, collect };

if (require.main === module) {
  const dir = process.argv[2] || '.';
  audit(dir).then((r) => {
    console.log(`\n  SCA · ${r.lockfile || 'no lockfile'} · ${r.deps} dependencies`);
    if (r.note) console.log(`  ${r.note}`);
    for (const f of r.findings) console.log(`  \x1b[31m●\x1b[0m ${f.name}@${f.version}  ${f.vulns.join(', ')}`);
    if (r.lockfile && !r.findings.length && !r.note) console.log('  \x1b[32m✓\x1b[0m no known-vulnerable versions');
    console.log();
  });
}
