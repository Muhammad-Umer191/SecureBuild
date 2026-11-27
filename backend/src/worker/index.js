// Dispatcher – forks scanWorker.js so scanning runs in a separate OS process.
// No Redis needed; uses Node.js built-in child_process.
const path  = require('path');
const { fork } = require('child_process');
const logger    = require('../utils/logger');

const WORKER_SCRIPT = path.join(__dirname, 'scanWorker.js');

/**
 * @param {{ mode: 'scan'|'refresh', repoId: string, scanId: string, repoUrl: string }} payload
 *        `mode` is a log label only; both modes run the same full scan.
 */
function dispatchScanJob(payload) {
  const child = fork(WORKER_SCRIPT, [], { stdio: 'inherit', detached: false });
  child.on('error', (err) => logger.error('[worker] fork failed: %s', err.message));
  child.on('exit', (code) => {
    if (code !== 0) logger.error('[worker] scanWorker exited with code %d for repo %s', code, payload.repoId);
  });
  child.send(payload);
  child.unref();
  return child;
}

module.exports = { dispatchScanJob };
