// Entry point – connects to Mongo, starts the worker, and listens.
const app = require('./app');
const config = require('./config');
const connectDB = require('./config/db');
const logger = require('./utils/logger');
// Background scan workers are spawned on-demand by dispatchScanJob() in worker/index.js
// No persistent queue process needed here.

(async () => {
  await connectDB();
  app.listen(config.port, () => {
    logger.info('SecureBuild API listening on port %d (%s)', config.port, config.nodeEnv);
  });
})();
