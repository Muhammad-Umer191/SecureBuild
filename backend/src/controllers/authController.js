const jwt = require('jsonwebtoken');
const config = require('../config');
const ApiError = require('../utils/ApiError');
const authQueries = require('../queries/authQueries');

function signToken(userId) {
  return jwt.sign({ sub: userId }, config.jwt.secret, {
    expiresIn: config.jwt.expiresIn,
  });
}

/** POST /api/auth/register */
exports.register = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    const existing = await authQueries.findUserByEmail(email);
    if (existing) {
      throw new ApiError(409, 'DUPLICATE', 'Email already registered');
    }

    const user = await authQueries.createUser({ name, email, password });
    const token = signToken(user._id);

    return res.status(201).json({
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    return next(err);
  }
};

/** POST /api/auth/login */
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await authQueries.findUserByEmail(email, true);
    if (!user || !(await user.comparePassword(password))) {
      throw new ApiError(401, 'AUTH_INVALID', 'Invalid email or password');
    }

    const token = signToken(user._id);
    return res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    return next(err);
  }
};

/** POST /api/auth/changePassword */
exports.changePassword = async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const user = await authQueries.findUserById(req.user._id, true);
    if (!user || !(await user.comparePassword(currentPassword))) {
      throw new ApiError(401, 'AUTH_INVALID', 'Current password is incorrect');
    }

    await authQueries.updateUserPassword(user, newPassword);
    return res.json({ message: 'Password updated successfully' });
  } catch (err) {
    return next(err);
  }
};

/** GET /api/auth/me */
exports.me = async (req, res) => {
  return res.json({
    user: { id: req.user._id, name: req.user.name, email: req.user.email },
  });
};
