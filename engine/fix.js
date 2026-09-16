'use strict';
/**
 * VulnHunter fix phase: "writes an exploit demo, creates a failing security
 * test (RED), implements the fix (GREEN), verifies the exploit is blocked".
 *
 * We generate the RED test deterministically from the finding's own evidence -
 * no model call. The test fails today; it must pass after the fix and keep
 * passing forever, so the bug cannot silently come back.
 */
const INV_TEMPLATES = {
  I1: f => ({
    name: `${f.route} must not leak another account's resource`,
    intent: 'A second account must not be able to read the first account\'s object.',
    code: `// RED: fails while the isolation bug is present
const owner  = await login(ACCOUNT_A);
const other  = await login(ACCOUNT_B);
const res    = await request('${f.method}', '${f.pathTemplate}'.replace(':id', OWNED_ID), other.token);
assert(res.status === 403 || res.status === 404,
  \`expected other account to be denied, got \${res.status}\`);`,
    remediation: 'Load the row, compare its owner column against the authenticated user id, and return 403/404 before serialising. Do the check server-side on every method, not just GET.',
  }),
  I2: f => ({
    name: `${f.route} must not serve operator-scope data to a regular user`,
    intent: 'A non-admin token must not receive records it does not own.',
    code: `const user = await login(ACCOUNT_B);
const res  = await request('${f.method}', '${f.pathTemplate}', user.token);
assert(res.status === 403 || ownedBy(res.body, user.id),
  'regular user received records owned by others');`,
    remediation: 'Scope the query by the caller (WHERE owner_id = :me) or gate the route behind a role check. Filtering in the UI is not a control.',
  }),
  I3: f => ({
    name: `${f.route} must require authentication`,
    intent: 'An anonymous request must not return user data.',
    code: `const res = await request('${f.method}', '${f.pathTemplate}', null);
assert(res.status === 401 || res.status === 403,
  \`anonymous request returned \${res.status}\`);`,
    remediation: 'Attach the auth middleware to this route. Verify the route table, not the file - routes registered outside the guarded router are the usual cause.',
  }),
  I4: f => ({
    name: `${f.route} must ignore privileged fields from the client`,
    intent: 'A client-supplied privileged field must not be persisted.',
    code: `const user = await login(ACCOUNT_B);
const res  = await request('${f.method}', '${f.pathTemplate}', user.token, { role: 'admin' });
assert(res.body?.role !== 'admin', 'client set a privileged field');`,
    remediation: 'Allow-list the updatable fields explicitly. Never spread the request body into the update statement.',
  }),
  I6: f => ({
    name: `${f.route} must not return server-only values`,
    intent: 'Secret-bearing fields must never be serialised to a client.',
    code: `const res = await request('${f.method}', '${f.pathTemplate}', (await login(ACCOUNT_B)).token);
assert(!/password|hash|secret|token|api[_-]?key/i.test(JSON.stringify(res.body)),
  'response carries a server-only field');`,
    remediation: 'Select explicit columns instead of SELECT *, or strip the field in a serializer shared by every route that returns this object.',
  }),
};

function redTest(finding) {
  const [method, ...rest] = finding.route.split(' ');
  const pathTemplate = rest.join(' ');
  const t = INV_TEMPLATES[finding.inv];
  if (!t) return null;
  const built = t({ ...finding, method, pathTemplate });
  return { ...built, inv: finding.inv, route: finding.route, method, pathTemplate,
           evidence: finding.evidence };
}

function plan(confirmed) {
  return confirmed.map(redTest).filter(Boolean);
}
module.exports = { plan, redTest };
