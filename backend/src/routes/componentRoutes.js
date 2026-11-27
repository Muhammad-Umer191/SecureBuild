const { Router } = require('express');
const authenticate = require('../middleware/auth');
const ownsRepo = require('../middleware/ownsRepo');
const validate = require('../middleware/validate');
const schemas = require('../validators/componentValidator');
const ctrl = require('../controllers/componentController');

const router = Router();

router.use(authenticate);

router.get('/show/:repoId', ownsRepo, validate(schemas.listComponents, 'query'), ctrl.listComponents);
router.get('/export/:repoId', ownsRepo, validate(schemas.exportSbom, 'query'), ctrl.exportSbom);

module.exports = router;
