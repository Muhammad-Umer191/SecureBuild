// Joi validation middleware factory.
const ApiError = require('../utils/ApiError');

/**
 * Returns a middleware that validates `req[source]` against a Joi schema.
 * @param {import('joi').ObjectSchema} schema  Joi schema
 * @param {'body'|'query'|'params'} source     Part of the request to validate (default: 'body')
 */
function validate(schema, source = 'body') {
  return (req, _res, next) => {
    const { error, value } = schema.validate(req[source], {
      abortEarly: false,
      stripUnknown: true,
    });

    if (error) {
      const message = error.details.map((d) => d.message).join('; ');
      return next(new ApiError(400, 'VALIDATION_ERROR', message));
    }

    req[source] = value;   // replace with sanitized values
    return next();
  };
}

module.exports = validate;
