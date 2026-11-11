// Bull queue for background scan jobs.
const Queue = require('bull');
const config = require('./index');
const logger = require('../utils/logger');

const scanQueue = new Queue('scan', config.redis.url, {
  defaultJobOptions: {
    attempts: 3,
    backoff: { type: 'exponential', delay: 5000 },
    removeOnComplete: 100,
    removeOnFail: 200,
  },
});

scanQueue.on('error', (err) => {
  logger.error('Queue error: %s', err.message);
});

module.exports = scanQueue;
