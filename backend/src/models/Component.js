const mongoose = require('mongoose');

const componentSchema = new mongoose.Schema(
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
    name: { type: String, required: true },
    version: { type: String, required: true },
    ecosystem: { type: String, required: true },
    purl: { type: String, required: true },
    direct: { type: Boolean, default: false },
    licenses: [String],
    vulnerabilityCount: { type: Number, default: 0 },
    maxSeverity: { type: String, default: null },
  },
  { timestamps: true },
);

// One component per purl per repo
componentSchema.index({ repo: 1, purl: 1 }, { unique: true });

module.exports = mongoose.model('Component', componentSchema);
