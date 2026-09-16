'use strict';
/**
 * E2B sandbox driver. Runs untrusted code (generated exploit scripts, a
 * customer's own snippet) inside an isolated Firecracker microVM instead of on
 * our host - the isolation the process driver refuses to fake.
 *
 * Contract matches the real @e2b/sdk v2.x:
 *   Sandbox.create({ apiKey, timeoutMs })
 *   sbx.files.write(path, content)
 *   sbx.commands.run(cmd, { timeoutMs }) -> { stdout, stderr, exitCode }
 *   sbx.updateNetwork({ allowInternet })   // network isolation control
 *   sbx.kill()
 *
 * The SDK is loaded lazily so the engine runs without it installed. A
 * `sandboxFactory` can be injected for testing against a mock.
 */
const { Sandbox } = require('./sandbox');

class E2BRunner {
  constructor({ apiKey = process.env.E2B_API_KEY, timeoutMs = 30000,
                allowInternet = false, sandboxFactory = null } = {}) {
    this.apiKey = apiKey;
    this.timeoutMs = timeoutMs;
    this.allowInternet = allowInternet;     // exploits run network-OFF by default
    this.sandboxFactory = sandboxFactory;   // inject for tests
  }

  async _createSandbox() {
    if (this.sandboxFactory) return this.sandboxFactory({ apiKey: this.apiKey, timeoutMs: this.timeoutMs });
    let mod;
    try { mod = require('e2b'); }
    catch { throw new Error('e2b SDK not installed; run `npm i e2b` or inject a sandboxFactory'); }
    if (!this.apiKey) throw new Error('E2B_API_KEY required to run untrusted code remotely');
    return mod.Sandbox.create({ apiKey: this.apiKey, timeoutMs: this.timeoutMs });
  }

  /**
   * Run one exploit script in a fresh, short-lived microVM (XBOW: workers
   * retired after each mission). Network off unless explicitly opened.
   * Returns { exitCode, stdout, stderr } with secrets redacted.
   */
  async runExploit({ script, runtime = 'node', filename = '/tmp/exploit.js', input = null }) {
    const sbx = await this._createSandbox();
    try {
      // network isolation: exploit code cannot phone home or attack third parties
      if (sbx.updateNetwork) await sbx.updateNetwork({ allowInternet: this.allowInternet });
      await sbx.files.write(filename, script);
      if (input) await sbx.files.write('/tmp/input.json', JSON.stringify(input));
      const cmd = runtime === 'python' ? `python3 ${filename}` : `node ${filename}`;
      const res = await sbx.commands.run(cmd, { timeoutMs: this.timeoutMs });
      return {
        exitCode: res.exitCode,
        stdout: Sandbox.redact(res.stdout || ''),
        stderr: Sandbox.redact(res.stderr || ''),
        isolated: !this.allowInternet,
      };
    } finally {
      try { await sbx.kill(); } catch {}   // always retire the VM
    }
  }

  static available() {
    try { require('e2b'); return true; } catch { return false; }
  }
}
module.exports = { E2BRunner };
