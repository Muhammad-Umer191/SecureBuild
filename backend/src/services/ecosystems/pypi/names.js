// Python package names are case- and separator-insensitive.

/** PEP 503: "Foo_Bar.baz" -> "foo-bar-baz", so differently written names match. */
const normalizePypiName = (name) => name.toLowerCase().replace(/[-_.]+/g, '-');

module.exports = { normalizePypiName };
