// MongoDB connection via Mongoose.
const mongoose = require('mongoose');
const logger = require('../utils/logger');
const config = require('./index');

async function connectDB() {
  try {
    await mongoose.connect(config.mongo.uri);
    logger.info('MongoDB connected: %s', mongoose.connection.host);
  } catch (err) {
    logger.error('MongoDB connection error: %s', err.message);
    process.exit(1);
  }
}

module.exports = connectDB;
