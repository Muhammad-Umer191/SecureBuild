// Express application setup (separated from server.js for testability).
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const config = require('./config');

const authRoutes = require('./routes/authRoutes');
const scanRoutes = require('./routes/scanRoutes');
const vulnerabilityRoutes = require('./routes/vulnerabilityRoutes');
const cveRoutes = require('./routes/cveRoutes');
const errorHandler = require('./middleware/errorHandler');

const app = express();

// ── Security & parsing ─────────────────────────────────
app.use(helmet());
app.use(cors({ origin: config.cors.origin, credentials: true }));
app.use(express.json({ limit: '1mb' }));

// ── Request logging ────────────────────────────────────
if (config.nodeEnv !== 'test') {
  app.use(morgan('dev'));
}

// ── Health check ───────────────────────────────────────
app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));

// ── Routes ─────────────────────────────────────────────
app.use('/api/auth', authRoutes);
app.use('/api/scan', scanRoutes);
app.use('/api/vulnerability', vulnerabilityRoutes);
app.use('/api/cve', cveRoutes);

// ── Error handler (must be last) ───────────────────────
app.use(errorHandler);

module.exports = app;
