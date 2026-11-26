#!/usr/bin/env node
// Initializes the MongoDB database collections and indexes from the Mongoose models.
// Usage: node src/scripts/initDb.js
const mongoose = require('mongoose');
const connectDB = require('../config/db');
const models = require('../models');
const logger = require('../utils/logger');

async function initDb() {
  await connectDB();

  const entries = Object.entries(models);
  for (const [name, Model] of entries) {
    await Model.createCollection();
    await Model.syncIndexes();
    logger.info('Initialized collection & indexes for %s (%s)', name, Model.collection.name);
  }

  const dbName = mongoose.connection.name;
  const collections = await mongoose.connection.db.listCollections().toArray();
  logger.info(
    'Database "%s" ready with %d collections: %s',
    dbName,
    collections.length,
    collections.map((c) => c.name).join(', '),
  );

  await mongoose.disconnect();
}

initDb().catch(async (err) => {
  logger.error('Failed to initialize database: %s', err.message);
  await mongoose.disconnect().catch(() => {});
  process.exit(1);
});
