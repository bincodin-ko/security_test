'use strict';
/**
 * SAST-lite + secret scanning. Rule-based source review: it flags *candidates*,
 * not confirmed exploits. That distinction is the whole product thesis — a
 * static match ("this line concatenates input into SQL") is a suspicion; the
 * dynamic engine (I7) is what turns it into a proven bug. So this module is best
 * used as a candidate feeder: its SQL-sink hit at server.js:NNN is the same
 * defect I7 confirms by execution at runtime.
 *
 * Needs the repository source. Deterministic, offline, no model.
 */
const fs = require('fs');
const path = require('path');

const RULES = [
  { id: 'hardcoded-secret', sev: 'high', kind: '하드코딩된 시크릿',
    re: /\b(?:const|let|var)\s+\w*(?:secret|password|passwd|api[_-]?key|token|private[_-]?key)\w*\s*=\s*['"][^'"]{4,}['"]/i },
  { id: 'sql-string-build', sev: 'critical', kind: 'SQL 문자열 조립(주입 위험)',
    re: /\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|LIKE|LIMIT|ORDER\s+BY)\b[^\n`]{0,80}?(?:\$\{|["']\s*\+\s*\w)/i },
  { id: 'eval', sev: 'high', kind: '동적 실행(eval/Function)', re: /\beval\s*\(|new\s+Function\s*\(/ },
  { id: 'child-exec', sev: 'high', kind: '셸 실행에 입력 결합', re: /\b(?:exec|execSync|spawn)\s*\([^)]*(?:\$\{|\+\s*req\.)/ },
  { id: 'weak-hash', sev: 'medium', kind: '약한 해시(md5/sha1)', re: /createHash\(\s*['"](?:md5|sha1)['"]\s*\)/i },
  { id: 'stack-to-client', sev: 'medium', kind: '스택 트레이스 클라이언트 노출', re: /res\.(?:status\(\d+\)\.)?json\([^)]*\.stack/ },
  { id: 'cors-wildcard-creds', sev: 'medium', kind: 'CORS 와일드카드 + credentials',
    re: /Access-Control-Allow-Origin['"]\s*,\s*['"]\*/ },
  { id: 'dangerous-html', sev: 'high', kind: 'React dangerouslySetInnerHTML', re: /dangerouslySetInnerHTML/ },
];

function walk(dir) {
  const files = [];
  (function rec(d) {
    for (const f of fs.readdirSync(d, { withFileTypes: true })) {
      if (f.name === 'node_modules' || f.name.startsWith('.')) continue;
      const p = path.join(d, f.name);
      if (f.isDirectory()) rec(p);
      else if (/\.(js|ts|mjs|cjs|jsx|tsx)$/.test(f.name)) files.push(p);
    }
  })(dir);
  return files;
}

function scan(dir) {
  const findings = [];
  for (const file of walk(dir)) {
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    lines.forEach((line, i) => {
      if (line.length > 400) return;
      for (const rule of RULES) {
        if (rule.re.test(line)) findings.push({
          rule: rule.id, kind: rule.kind, sev: rule.sev,
          file: path.relative(dir, file), line: i + 1,
          code: line.trim().slice(0, 120),
        });
      }
    });
  }
  const order = { critical: 0, high: 1, medium: 2 };
  findings.sort((a, b) => order[a.sev] - order[b.sev]);
  return findings;
}

module.exports = { scan };

if (require.main === module) {
  const dir = process.argv[2] || '.';
  const f = scan(dir);
  console.log(`\n  SAST · ${f.length} candidate(s) in ${dir}`);
  const color = { critical: '\x1b[31m', high: '\x1b[33m', medium: '\x1b[36m' };
  for (const x of f) console.log(`  ${color[x.sev]}● ${x.sev}\x1b[0m  ${x.file}:${x.line}  ${x.kind}\n         ${x.code}`);
  console.log('\n  note: candidates only — confirm reachable ones by execution (I7).\n');
}
