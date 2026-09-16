'use strict';
/**
 * Route discovery. The point: the scanner must NOT be told what endpoints exist.
 * Three independent sources, merged. Real products add OpenAPI + HAR + crawl.
 */
const fs = require('fs');
const path = require('path');
const { discoverNext } = require('./discover-next');

function isNextApp(dir) {
  return !!dir && (fs.existsSync(path.join(dir, 'app')) || fs.existsSync(path.join(dir, 'pages')));
}

// --- Source 1: parse server source for framework route registrations -------
function fromSource(dir) {
  const routes = [];
  const files = [];
  (function walk(d) {
    for (const f of fs.readdirSync(d, { withFileTypes: true })) {
      if (f.name === 'node_modules' || f.name.startsWith('.')) continue;
      const p = path.join(d, f.name);
      if (f.isDirectory()) walk(p);
      else if (/\.(js|ts|mjs)$/.test(f.name)) files.push(p);
    }
  })(dir);

  // app.get('/path', mw?, handler)  |  router.post("/path", ...)
  const re = /\b(?:app|router)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]\s*(,\s*([A-Za-z_$][\w$]*)\s*)?,/g;
  for (const file of files) {
    const src = fs.readFileSync(file, 'utf8');
    let m;
    while ((m = re.exec(src))) {
      routes.push({
        method: m[1].toUpperCase(),
        path: m[2],
        guard: m[4] && m[4] !== 'async' ? m[4] : null, // named middleware, if any
        source: `${path.relative(dir, file)}`,
      });
    }
  }
  return routes;
}

// --- Source 2: probe a wordlist of conventional paths ----------------------
const COMMON = [
  '/api/health', '/api/status', '/api/config', '/api/debug/config',
  '/api/users', '/api/me', '/api/admin', '/api/admin/users',
  '/api/internal/metrics', '/.env', '/.git/config', '/swagger.json',
  '/openapi.json', '/api-docs',
];
async function fromProbe(base) {
  const found = [];
  await Promise.all(COMMON.map(async p => {
    try {
      const r = await fetch(base + p, { method: 'GET' });
      if (r.status !== 404) found.push({ method: 'GET', path: p, guard: null, source: 'probe' });
    } catch {}
  }));
  return found;
}

// --- Source 3: OpenAPI, if the app publishes one --------------------------
async function fromOpenAPI(base) {
  for (const p of ['/openapi.json', '/swagger.json', '/api-docs']) {
    try {
      const r = await fetch(base + p);
      if (!r.ok) continue;
      const spec = await r.json();
      if (!spec.paths) continue;
      const out = [];
      for (const [pth, ops] of Object.entries(spec.paths))
        for (const method of Object.keys(ops))
          out.push({ method: method.toUpperCase(), path: pth, guard: null, source: 'openapi' });
      return out;
    } catch {}
  }
  return [];
}

async function discover({ base, sourceDir }) {
  const sourceRoutes = sourceDir && fs.existsSync(sourceDir)
    ? (isNextApp(sourceDir) ? discoverNext(sourceDir) : fromSource(sourceDir))
    : [];
  const all = [
    ...sourceRoutes,
    ...(await fromOpenAPI(base)),
    ...(await fromProbe(base)),
  ];
  const seen = new Map();
  for (const r of all) {
    const k = `${r.method} ${r.path}`;
    if (!seen.has(k)) seen.set(k, r);
  }
  return [...seen.values()].sort((a, b) => a.path.localeCompare(b.path));
}

module.exports = { discover };
