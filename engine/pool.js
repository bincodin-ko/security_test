'use strict';
/**
 * XBOW: "agents that attack and validators that confirm" with short-lived
 * workers retired after each mission. Here: a bounded concurrency pool where
 * every task gets a fresh context object and cannot leak state to the next.
 */
async function pool(items, worker, { concurrency = 6, onProgress } = {}) {
  const results = new Array(items.length);
  let cursor = 0, done = 0;
  const runners = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    for (;;) {
      const i = cursor++;
      if (i >= items.length) return;
      try { results[i] = await worker(items[i], i); }
      catch (e) { results[i] = { error: String(e && e.message || e) }; }
      if (onProgress) onProgress(++done, items.length);
    }
  });
  await Promise.all(runners);
  return results;
}
module.exports = { pool };
