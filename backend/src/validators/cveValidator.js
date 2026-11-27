const Joi = require('joi');

// Shape check only; the CVE service does the strict check before any network call.
const cveParams = Joi.object({
  cveId: Joi.string().trim().max(20).pattern(/^CVE-\d{4}-\d{4,7}$/i).required()
    .messages({ 'string.pattern.base': 'cveId must look like CVE-2021-44228' }),
});

module.exports = { cveParams };
