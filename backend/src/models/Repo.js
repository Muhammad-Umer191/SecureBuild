const mongoose = require('mongoose');

const repoSchema = new mongoose.Schema(
  {
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    url: {
      type: String,
      required: true,
      trim: true,
      // Only allow github.com URLs
      validate: {
        validator: (v) => /^https:\/\/github\.com\/[\w.\-]+\/[\w.\-]+\/?$/.test(v),
        message: 'Only github.com/owner/repo URLs are allowed',
      },
    },
    name: {
      type: String,
      required: true,
      trim: true,
    },
    lastScan: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Scan',
      default: null,
    },
    status: {
      type: String,
      enum: ['idle', 'scanning', 'error'],
      default: 'idle',
    },
  },
  { timestamps: true },
);

// One user cannot add the same repo URL twice
repoSchema.index({ owner: 1, url: 1 }, { unique: true });

module.exports = mongoose.model('Repo', repoSchema);
