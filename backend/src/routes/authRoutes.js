const { Router } = require('express');
const rateLimit = require('express-rate-limit');
const validate = require('../middleware/validate');
const authenticate = require('../middleware/auth');
const schemas = require('../validators/authValidator');
const ctrl = require('../controllers/authController');

const router = Router();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { code: 'RATE_LIMITED', message: 'Too many attempts, try again later' } },
});

router.post('/register', authLimiter, validate(schemas.register), ctrl.register);
router.post('/login', authLimiter, validate(schemas.login), ctrl.login);
router.post('/changePassword', authenticate, validate(schemas.changePassword), ctrl.changePassword);
router.get('/me', authenticate, ctrl.me);

module.exports = router;
