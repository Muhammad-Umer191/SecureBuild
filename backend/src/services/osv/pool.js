// Runs an async task for each item, at most `limit` at a time. Stops starting
// new tasks after the first failure and rejects with that error.

/**
 * @param {Array} items
 * @param {number} limit
 * @param {(item: any) => Promise<void>} worker
 */
async function runPool(items, limit, worker) {
  let next = 0;
  let failed = false;
  const runner = async () => {
    while (!failed && next < items.length) {
      const item = items[next];
      next += 1;
      try {
        await worker(item);
      } catch (err) {
        failed = true;
        throw err;
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, runner));
}

module.exports = { runPool };
