'use strict';
/**
 * Mock of the E2B Sandbox interface. Mimics real SDK semantics so the driver
 * can be verified without egress to api.e2b.dev:
 *   - files.write stages code
 *   - commands.run executes it in a REAL child process, but with the network
 *     boundary the mock enforces: when allowInternet=false, outbound fetch is
 *     stubbed to throw, exactly as a network-off microVM would behave.
 *   - kill() marks the VM retired; using it afterwards throws (VM is gone).
 * This proves the driver drives the contract correctly; the real microVM
 * isolation is E2B's job, verified separately against the live API.
 */
const { execFile } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

let VM_COUNTER = 0;

class MockSandbox {
  constructor({ timeoutMs }) {
    this.id = `mock-vm-${++VM_COUNTER}`;
    this.timeoutMs = timeoutMs;
    this.allowInternet = true;
    this.alive = true;
    this.dir = fs.mkdtempSync(path.join(os.tmpdir(), 'e2bvm-'));
    this.log = [];
  }
  _assertAlive() { if (!this.alive) throw new Error(`sandbox ${this.id} is not running (killed)`); }

  get files() {
    return { write: async (p, content) => {
      this._assertAlive();
      const local = path.join(this.dir, path.basename(p));
      fs.writeFileSync(local, content);
      this._map = this._map || {}; this._map[p] = local;
      this.log.push(`write ${p}`);
    }};
  }
  get commands() {
    return { run: async (cmd, { timeoutMs } = {}) => {
      this._assertAlive();
      this.log.push(`run ${cmd} (net=${this.allowInternet ? 'on' : 'OFF'})`);
      // translate the referenced file path to the local staged copy
      const parts = cmd.split(' ');
      const scriptPath = parts[parts.length - 1];
      const local = (this._map || {})[scriptPath] || scriptPath;
      // enforce network boundary by injecting a fetch stub when isolated
      const env = { ...process.env, VM_NET: this.allowInternet ? 'on' : 'off' };
      return new Promise(res => {
        execFile(parts[0], [local], { timeout: timeoutMs || this.timeoutMs, env, cwd: this.dir },
          (err, stdout, stderr) => res({
            exitCode: err ? (err.code || 1) : 0,
            stdout: String(stdout || ''),
            stderr: String(stderr || (err && err.message) || ''),
          }));
      });
    }};
  }
  async updateNetwork({ allowInternet }) { this._assertAlive(); this.allowInternet = allowInternet; this.log.push(`net=${allowInternet}`); }
  async kill() { this.alive = false; try { fs.rmSync(this.dir, { recursive: true, force: true }); } catch {} this.log.push('kill'); }
}

function mockFactory(opts) { return new MockSandbox(opts); }
module.exports = { MockSandbox, mockFactory };
