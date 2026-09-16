'use strict';
/**
 * Vibe App Scanner hands the fix to the user's AI tool "over MCP or
 * copy-paste". The vibe-coder's actual motion is pasting into an agent, so the
 * deliverable is a prompt that carries the proof, not a CWE id.
 * Secrets are redacted before anything leaves the process.
 */
const { Sandbox } = require('./sandbox');

function toPrompt(f, red) {
  return [
    `Fix a confirmed security bug in this app.`,
    ``,
    `Endpoint: ${f.route}`,
    `Problem:  ${f.title}`,
    `Proof:    ${Sandbox.redact(f.evidence || '')}`,
    ``,
    `This was confirmed by actually performing the attack, not by static analysis.`,
    red ? `Required fix: ${red.remediation}` : '',
    red ? `` : '',
    red ? `Add a regression test asserting: ${red.intent}` : '',
    ``,
    `Do not weaken any other check to make this pass.`,
  ].filter(Boolean).join('\n');
}

function exportAll(confirmed, redTests) {
  const byRoute = new Map(redTests.map(t => [`${t.inv}|${t.route}`, t]));
  return {
    version: 1,
    generated: new Date().toISOString(),
    findings: confirmed.map(f => {
      const red = byRoute.get(`${f.inv}|${f.route}`);
      return {
        id: `${f.inv}-${f.route.replace(/[^\w]+/g, '-')}`.toLowerCase(),
        invariant: f.inv, route: f.route, title: f.title,
        proof: Sandbox.redact(f.evidence || ''),
        remediation: red ? red.remediation : null,
        regressionTest: red ? red.code : null,
        agentPrompt: toPrompt(f, red),
      };
    }),
  };
}
module.exports = { exportAll, toPrompt };
