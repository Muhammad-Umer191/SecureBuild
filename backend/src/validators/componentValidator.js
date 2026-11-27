const Joi = require('joi');

const csv = (allowed) => Joi.string().trim().max(100)
  .pattern(new RegExp(`^(${allowed.join('|')})(,(${allowed.join('|')}))*$`))
  .messages({ 'string.pattern.base': `{#label} must be a comma list of: ${allowed.join(', ')}` });

const listComponents = Joi.object({
  ecosystem: csv(['npm', 'PyPI']),
  direct: Joi.string().valid('true', 'false'),
  vulnerable: Joi.string().valid('true', 'false'),
  q: Joi.string().trim().max(100).allow(''),
  sort: Joi.string().valid('name', 'vulns', 'ecosystem').default('name'),
  order: Joi.string().valid('asc', 'desc').default('asc'),
  page: Joi.number().integer().min(1).max(10000).default(1),
  limit: Joi.number().integer().min(1).max(200).default(50),
});

const exportSbom = Joi.object({
  format: Joi.string().valid('cyclonedx').default('cyclonedx')
    .messages({ 'any.only': 'only format=cyclonedx is supported' }),
});

module.exports = { listComponents, exportSbom };
