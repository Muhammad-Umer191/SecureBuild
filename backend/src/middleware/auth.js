// JWT authentication middleware.
const jwt = require('jsonwebtoken');
const config = require('../config');
const ApiError = require('../utils/ApiError');
const { User } = require('../models');

/**
 * Verifies the Bearer token and attaches `req.user` (the full user doc minus password).
 */
async function authenticate(req, _res, next) {
  try {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      throw new ApiError(401, 'AUTH_REQUIRED', 'Missing or malformed Authorization header');
    }

    const token = header.split(' ')[1];
    let payload;
    try {
      payload = jwt.verify(token, config.jwt.secret);
    } catch (err) {
      const msg = err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token';
      throw new ApiError(401, 'AUTH_INVALID', msg);
    }

    const user = await User.findById(payload.sub);
    if (!user) {
      throw new ApiError(401, 'AUTH_INVALID', 'User no longer exists');
    }

    req.user = user;
    return next();
  } catch (err) {
    return next(err);
  }
}

module.exports = authenticate;
