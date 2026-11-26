// Background job dispatcher – spawns scanWorker.js in a separate OS process
// so repo fetching and scanning never block the main Express server.
const path = require('path');
const { fork } = require('child_process');
const logger = require('../utils/logger');

const WORKER_SCRIPT = path.join(__dirname, 'scanWorker.js');

/**
 * Spawns a separate child process to run a scan or refresh job in the background.
 * @param {{ mode: 'scan'|'refresh', repoId: string, scanId: string, repoUrl: string, lastCommitSha?: string|null }} payload
 */
function dispatchScanJob(payload) {
  const child = fork(WORKER_SCRIPT, [], {
    stdio: 'inherit',
    detached: false,
  });

  child.on('error', (err) => {
    logger.error('Failed to spawn scanWorker process: %s', err.message);
  });

  child.send(payload);
  // Disconnect IPC channel once message is sent so parent doesn't hold onto it
  child.unref();
  return child;
}

module.exports = { dispatchScanJob };
