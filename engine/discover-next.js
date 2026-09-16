'use strict';
/**
 * Next.js route discovery. Next is the dominant vibe-coding stack (Lovable,
 * v0, Bolt all emit Next). Routes are FILE-SYSTEM based, so the path comes from
 * the file location, not a string literal - Express regex misses all of it.
 *
 *  App Router:   app/(star)(star)/route.{js,ts}   exporting GET/POST/...  -> that path
 *                app/api/users/[id]/route.ts   -> /api/users/:id
 *                app/(star)(star)/page.{tsx,jsx}         -> page (data-fetching surface)
 *  Pages Router: pages/api/(star)(star)/(star).{js,ts}  default export handler -> /api/...
 *
 * Guard detection: App Router handlers rarely name a middleware; auth usually
 * lives in middleware.ts or inside the handler. We surface the handler body so
 * the invariant engine can still probe it live.
 */
const fs = require('fs');
const path = require('path');

const HTTP = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

// app/api/users/[id]/route.ts -> /api/users/:id
// app/(marketing)/blog/route.ts -> /blog   (route groups (x) are stripped)
function appPathFromFile(rel) {
  let p = rel
    .replace(/^app/, '')
    .replace(/\/route\.(t|j)sx?$/, '')
    .replace(/\/page\.(t|j)sx?$/, '')
    .replace(/\/\([^)]+\)/g, '')       // (group) segments don't affect URL
    .replace(/\/@[^/]+/g, '')          // @slot parallel routes
    .replace(/\[\.\.\.([^\]]+)\]/g, '*')   // [...slug] catch-all
    .replace(/\[\[?\.\.\.([^\]]+)\]?\]/g, '*')
    .replace(/\[([^\]]+)\]/g, ':$1');  // [id] -> :id
  if (p === '') p = '/';
  return p;
}

// pages/api/legacy/login.ts -> /api/legacy/login ; pages/api/webhook.ts -> /api/webhook
function pagesPathFromFile(rel) {
  return rel
    .replace(/^pages/, '')
    .replace(/\/index\.(t|j)sx?$/, '')
    .replace(/\.(t|j)sx?$/, '')
    .replace(/\[\.\.\.([^\]]+)\]/g, '*')
    .replace(/\[([^\]]+)\]/g, ':$1') || '/';
}

function walk(dir, base = dir, acc = []) {
  if (!fs.existsSync(dir)) return acc;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, base, acc);
    else acc.push(path.relative(base, full));
  }
  return acc;
}

function discoverNext(root) {
  const routes = [];
  const appDir = path.join(root, 'app');
  const pagesDir = path.join(root, 'pages');

  // App Router route handlers
  for (const rel of walk(appDir, root)) {
    if (/\/route\.(t|j)sx?$/.test(rel)) {
      const src = fs.readFileSync(path.join(root, rel), 'utf8');
      const methods = HTTP.filter(m => new RegExp(`export\\s+(async\\s+)?function\\s+${m}\\b`).test(src)
                                    || new RegExp(`export\\s+const\\s+${m}\\b`).test(src));
      const urlPath = appPathFromFile(rel.replace(/\\/g, '/'));
      for (const m of methods) routes.push({ method: m, path: urlPath, guard: null, source: rel, kind: 'app-route' });
    }
    if (/\/page\.(t|j)sx?$/.test(rel)) {
      routes.push({ method: 'GET', path: appPathFromFile(rel.replace(/\\/g, '/')), guard: null, source: rel, kind: 'app-page' });
    }
    if (/\/actions\.(t|j)sx?$/.test(rel)) {
      const src = fs.readFileSync(path.join(root, rel), 'utf8');
      if (/['"]use server['"]/.test(src)) {
        const fns = [...src.matchAll(/export\s+async\s+function\s+(\w+)/g)].map(m => m[1]);
        for (const fn of fns) routes.push({ method: 'POST', path: appPathFromFile(rel.replace(/\\/g,'/').replace(/\/actions\.(t|j)sx?$/,'')) + `#${fn}`, guard: null, source: rel, kind: 'server-action' });
      }
    }
  }
  // Pages Router API
  for (const rel of walk(pagesDir, root)) {
    const r = rel.replace(/\\/g, '/');
    if (/^pages\/api\//.test(r) && /\.(t|j)sx?$/.test(r)) {
      routes.push({ method: 'ALL', path: pagesPathFromFile(r), guard: null, source: rel, kind: 'pages-api' });
    }
  }
  // dedupe
  const seen = new Map();
  for (const r of routes) { const k = `${r.method} ${r.path}`; if (!seen.has(k)) seen.set(k, r); }
  return [...seen.values()].sort((a, b) => a.path.localeCompare(b.path));
}
module.exports = { discoverNext, appPathFromFile, pagesPathFromFile };
