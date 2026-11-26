const Joi = require('joi');

const GITHUB_RE = /^https:\/\/github\.com\/[\w.\-]+\/[\w.\-]+\/?$/;

const addRepo = Joi.object({
  url: Joi.string().trim().pattern(GITHUB_RE).required().messages({
    'string.pattern.base': 'Only github.com/owner/repo URLs are allowed',
  }),
});

module.exports = { addRepo };
