// Python package names and purls.
//
// PyPI treats names as case- and separator-insensitive: "Flask_Login",
// "flask.login" and "flask-login" are the same package. PEP 503 defines one
// normalized spelling, used for matching, de-duplication and the purl.
const { buildPurl } = require('../../common/purl');

/** PEP 503: "Foo_Bar.baz" -> "foo-bar-baz", so differently written names match. */
const normalizePypiName = (name) => name.toLowerCase().replace(/[-_.]+/g, '-');

/** "Flask_Login", "0.6.2" -> "pkg:pypi/flask-login@0.6.2" */
const pypiPurl = (name, version) => buildPurl('pypi', null, normalizePypiName(name), version);

module.exports = { normalizePypiName, pypiPurl };
