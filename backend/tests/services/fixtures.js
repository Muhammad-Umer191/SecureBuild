// Loads the parser fixtures.
const fs = require('node:fs');
const path = require('node:path');
const { parse: parseToml } = require('smol-toml');

const dir = path.join(__dirname, 'fixtures');
const text = (name) => fs.readFileSync(path.join(dir, name), 'utf8');
const json = (name) => JSON.parse(text(name));
const toml = (name) => parseToml(text(name));

module.exports = { text, json, toml };
