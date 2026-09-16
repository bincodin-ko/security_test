'use strict';
/**
 * XBOW runs exploits inside an isolated container. Two drivers here.
 *
 * The control that actually matters for a URL scanner is EGRESS. A scanner
 * that will fire arbitrary requests at a host the user names is, if unguarded,
 * a relay for attacking third parties. Every request goes through guard().
 *
 *   'process' - works today: allow-listed host, private-range block, timeout,
 *               request cap, output redaction.
 *   'docker'  - stronger, for running customer code or generated exploit
 *               scripts. Requires a reachable daemon; UNVERIFIED in this env.
 */
const { execFile } = require('child_process');
const dns = require('dns').promises;
const net = require('net');

const PRIVATE = [
  /^10\./, /^127\./, /^192\.168\./, /^169\.254\./, /^::1$/, /^fc00:/, /^fe80:/,
  /^172\.(1[6-9]|2\d|3[01])\./,
];
const SECRET_RE = /((?:password|passwd|secret|token|api[_-]?key|authorization)"?\s*[:=]\s*"?)([^",\s}]{4,})/gi;
// PII value patterns: email, and common secret-id prefixes (Stripe cus_/sk_, etc.)
const EMAIL_RE = /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g;
const IDPREFIX_RE = /\b((?:cus|sk|pk|rk|whsec|tok|card|acct)_[A-Za-z0-9]{2,})/g;

class Sandbox {
  constructor({ allowHosts = [], maxRequests = 2000, timeoutMs = 10000,
                allowPrivate = false, driver = 'process' } = {}) {
    Object.assign(this, { allowHosts, maxRequests, timeoutMs, allowPrivate, driver });
    this.used = 0;
    this.blocked = [];
  }

  /** Resolve + allow-list check. Blocks SSRF-by-proxy and cloud metadata. */
  async guard(url) {
    const u = new URL(url);
    if (!this.allowHosts.includes(u.hostname))
      throw new Error(`egress blocked: ${u.hostname} is not an allowed target`);
    if (!this.allowPrivate) {
      let addrs = [];
      if (net.isIP(u.hostname)) addrs = [u.hostname];
      else try { addrs = (await dns.lookup(u.hostname, { all: true })).map(a => a.address); } catch { }
      for (const a of addrs)
        if (PRIVATE.some(re => re.test(a)))
          throw new Error(`egress blocked: ${u.hostname} resolves to private address ${a}`);
    }
    if (++this.used > this.maxRequests)
      throw new Error(`request cap reached (${this.maxRequests})`);
  }

  async fetch(url, opts = {}) {
    await this.guard(url);
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), this.timeoutMs);
    try { return await fetch(url, { ...opts, signal: ac.signal, redirect: 'manual' }); }
    finally { clearTimeout(t); }
  }

  /** Never let a captured secret reach a report, a log, or an LLM prompt. */
  static redact(s) {
    return String(s)
      .replace(SECRET_RE, (_, k, v) => k + v.slice(0, 4) + '…[redacted]')
      .replace(EMAIL_RE, m => m.slice(0, 2) + '…@…[redacted]')
      .replace(IDPREFIX_RE, m => m.split('_')[0] + '_…[redacted]');
  }

  /** Run untrusted code. Docker driver when available; refuses otherwise. */
  async run(cmd, args, { image = 'node:22-alpine' } = {}) {
    if (this.driver !== 'docker')
      throw new Error('refusing to execute untrusted code without container isolation');
    return new Promise((res, rej) => {
      execFile('docker', ['run', '--rm', '--network=none', '--read-only',
        '--memory=512m', '--cpus=1', '--pids-limit=128',
        '--cap-drop=ALL', '--security-opt=no-new-privileges',
        image, cmd, ...args],
        { timeout: this.timeoutMs }, (e, so, se) => e ? rej(e) : res({ stdout: so, stderr: se }));
    });
  }

  static async dockerAvailable() {
    return new Promise(r => execFile('docker', ['info'], { timeout: 4000 }, e => r(!e)));
  }
}
module.exports = { Sandbox };
