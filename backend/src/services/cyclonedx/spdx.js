// SPDX license identifiers ("MIT", "Apache-2.0", ...), taken from the official
// CycloneDX 1.5 schema file, so what we write as a license `id` is exactly
// what the schema accepts. Matching ignores case ("mit" -> "MIT").
const { enum: SPDX_IDS } = require('./schema/spdx.schema.json');

const byLowercase = new Map(SPDX_IDS.map((id) => [id.toLowerCase(), id]));

/** The canonical SPDX ID for `text`, or null if it isn't one. */
function spdxId(text) {
  return byLowercase.get(String(text).toLowerCase()) || null;
}

module.exports = { spdxId };
