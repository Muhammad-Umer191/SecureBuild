// Checks a document against the official CycloneDX 1.5 JSON schema (the same
// three files the module ships in src/services/cyclonedx/schema).
// Returns a list of human-readable errors; empty = valid.
const Ajv = require('ajv');
const addFormats = require('ajv-formats');
const bomSchema = require('../../../src/services/cyclonedx/schema/bom-1.5.schema.json');
const spdxSchema = require('../../../src/services/cyclonedx/schema/spdx.schema.json');
const jsfSchema = require('../../../src/services/cyclonedx/schema/jsf-0.82.schema.json');

const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
// Two formats the schema uses that ajv-formats doesn't define:
ajv.addFormat('iri-reference', /^\S+$/u);           // a URL that may contain non-ASCII characters
ajv.addFormat('idn-email', /^[^\s@]+@[^\s@]+$/u);    // an email that may contain non-ASCII characters
ajv.addSchema(spdxSchema, 'spdx.schema.json');
ajv.addSchema(jsfSchema, 'jsf-0.82.schema.json');
const validate = ajv.compile(bomSchema);

function allowed(e) {
  const values = e.params && e.params.allowedValues;
  if (!values) return '';
  return ` (${values.slice(0, 8).join(', ')}${values.length > 8 ? `, ... ${values.length - 8} more` : ''})`;
}

function validateBom(bom) {
  if (validate(bom)) return [];
  return validate.errors.map((e) => `${e.instancePath || '(root)'} ${e.message}${allowed(e)}`);
}

module.exports = { validateBom };
