// Custom error class for operational API errors.
class ApiError extends Error {
  /**
   * @param {number} status  HTTP status code (e.g. 400, 401, 404)
   * @param {string} code    Machine-readable code (e.g. 'VALIDATION_ERROR')
   * @param {string} message Human-readable message
   */
  constructor(status, code, message) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

module.exports = ApiError;
