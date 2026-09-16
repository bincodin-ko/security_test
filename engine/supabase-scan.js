'use strict';
/** CLI: node supabase-scan.js <project-url> <anon-key> [--write] */
const { audit } = require('./supabase');
const { Sandbox } = require('./sandbox');

(async () => {
  const [,, base, anonKey, ...flags] = process.argv;
  if (!base || !anonKey) {
    console.error('usage: node supabase-scan.js <project-url> <anon-key> [--write]');
    process.exit(1);
  }
  const probeWrite = flags.includes('--write');
  const r = await audit({ base, anonKey, probeWrite });

  const conf = r.findings.filter(f => f.verdict === 'confirmed').sort((a,b)=>b.severity-a.severity);
  const notes = r.findings.filter(f => f.verdict === 'needs_validation');

  console.log(`\n  Supabase RLS scan`);
  console.log(`  tables discovered : ${r.tablesFound}`);
  console.log(`  write probing     : ${probeWrite ? 'ON' : 'OFF (read-only; pass --write to test inserts)'}\n`);
  for (const f of conf) {
    console.log(`  \x1b[31m● ${f.severity}/5\x1b[0m  ${f.table}  —  ${f.title}`);
    console.log(`         ${Sandbox.redact(f.evidence)}`);
    console.log(`         fix: ${f.fix}\n`);
  }
  for (const f of notes) {
    console.log(`  \x1b[33m● note\x1b[0m  ${f.table}  —  ${f.title}\n`);
  }
  if (r.secure.length) console.log(`  \x1b[32m✓\x1b[0m secure to anon: ${r.secure.join(', ')}`);
  console.log(`\n  ${conf.length} confirmed, ${notes.length} note(s), ${r.secure.length} passed`);
})();
