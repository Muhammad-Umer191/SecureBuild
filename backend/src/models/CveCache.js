const mongoose = require('mongoose');

// Cache of cvelistV5 lookups (F2 fallback lookup). MongoDB removes an entry
// once `expiresAt` has passed (TTL index), so stale scores refresh on their own.
const cveCacheSchema = new mongoose.Schema({
  cveId: { type: String, required: true, unique: true },
  found: { type: Boolean, required: true },
  data: { type: mongoose.Schema.Types.Mixed, default: null },
  fetchedAt: { type: Date, required: true },
  expiresAt: { type: Date, required: true },
});

cveCacheSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('CveCache', cveCacheSchema);
