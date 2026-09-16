'use strict';
/**
 * Aikido "continuous" made real: a tick loop that decides what to run on each
 * trigger and never runs a full sweep when nothing changed. LLM-free.
 * In production the triggers are a deploy webhook + cron; here we drive it.
 */
const { discover } = require('./discover');
const watch = require('./watch');
const fs = require('fs');

async function tick({ base, sourceDir, state, trigger, hoursSinceFull }) {
  fs.mkdirSync(state, { recursive: true });
  const routes = await discover({ base, sourceDir });
  const surface = watch.diffSurface(`${state}/surface.json`, routes);
  const decision = watch.plan({ trigger, surface, hoursSinceFull });
  return { trigger, decision, surface: { added: surface.added, removed: surface.removed, changed: surface.changed } };
}
module.exports = { tick };
