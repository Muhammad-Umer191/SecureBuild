const mongoose = require('mongoose');

const cveSubSchema = new mongoose.Schema(
  {
    cveId: String,
    state: String,
    score: Number,
    severity: String,
    cvssVersion: String,
    vector: String,
    source: String,
    description: String,
    published: String,
    url: String,
    error: String,
  },
  { _id: false },
);

const ignoreSubSchema = new mongoose.Schema(
  {
    reason: { type: String, required: true },
    by: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    at: { type: Date, default: Date.now },
  },
  { _id: false },
);

const refSubSchema = new mongoose.Schema(
  {
    type: { type: String, enum: ['ADVISORY', 'WEB', 'FIX', 'PACKAGE', 'ARTICLE'] },
    url: String,
  },
  { _id: false },
);

const packageSubSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    version: { type: String, required: true },
    ecosystem: { type: String, required: true },
    purl: { type: String, required: true },
  },
  { _id: false },
);

const findingSchema = new mongoose.Schema(
  {
    repo: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Repo',
      required: true,
      index: true,
    },
    scan: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Scan',
      required: true,
    },
    vulnId: { type: String, required: true },
    aliases: [String],
    cveIds: [String],
    summary: { type: String, required: true },
    details: String,
    package: { type: packageSubSchema, required: true },
    direct: { type: Boolean, default: false },
    cvssVector: { type: String, default: null },
    score: { type: Number, default: null },
    severity: {
      type: String,
      enum: ['critical', 'high', 'medium', 'low', 'none', 'unknown'],
      default: 'unknown',
    },
    scoreSource: { type: String, default: null },
    hasFix: { type: Boolean, default: false },
    fixedVersions: [String],
    recommendedFix: { type: String, default: null },
    dependencyPath: [String],
    references: [refSubSchema],
    cwes: [String],
    cves: [cveSubSchema],
    scoring: {
      explanation: String,
      thresholds: {
        critical: { type: Number, default: 9.0 },
        high: { type: Number, default: 7.0 },
        medium: { type: Number, default: 4.0 },
        low: { type: Number, default: 0.1 },
      },
    },
    published: Date,
    modified: Date,
    firstSeenAt: { type: Date, default: Date.now },

    // Status management
    status: {
      type: String,
      enum: ['open', 'ignored'],
      default: 'open',
    },
    ignore: {
      type: ignoreSubSchema,
      default: null,
    },
  },
  { timestamps: true },
);

// Compound index for listing findings by repo + status
findingSchema.index({ repo: 1, status: 1 });
// Avoid duplicate vulnId per repo (latest scan wins via upsert)
findingSchema.index({ repo: 1, vulnId: 1 }, { unique: true });

module.exports = mongoose.model('Finding', findingSchema);
