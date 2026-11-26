const { Router } = require('express');
const authenticate = require('../middleware/auth');
const ownsRepo = require('../middleware/ownsRepo');
const validate = require('../middleware/validate');
const schemas = require('../validators/scanValidator');
const ctrl = require('../controllers/scanController');

const router = Router();

router.use(authenticate);

router.post('/addRepo', validate(schemas.addRepo), ctrl.addRepo);
router.get('/fetchRepos', ctrl.fetchRepos);
router.post('/refreshRepo/:repoId', ownsRepo, ctrl.refreshRepo);

module.exports = router;
