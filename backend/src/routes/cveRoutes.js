const { Router } = require('express');
const rateLimit = require('express-rate-limit');
const authenticate = require('../middleware/auth');
const validate = require('../middleware/validate');
const schemas = require('../validators/cveValidator');
const ctrl = require('../controllers/cveController');

const router = Router();

// Each uncached lookup is a request to GitHub, so limit it per user.
const cveLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: (req) => req.app.locals.cveRateLimit || 30,
  keyGenerator: (req) => `user:${req.user._id}`,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { code: 'RATE_LIMITED', message: 'Too many CVE lookups, try again in a minute' } },
});

router.use(authenticate);

router.get('/:cveId', cveLimiter, validate(schemas.cveParams, 'params'), ctrl.getCve);

module.exports = router;
