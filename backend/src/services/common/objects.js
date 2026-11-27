// Safe access to values parsed from untrusted files.
//
// Values are type-checked before use, and objects are only read through
// Object.entries/keys (never `obj[name]` with a name taken from the file), so
// names like "__proto__" can't cause trouble.

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const entriesOf = (v) => (isObject(v) ? Object.entries(v) : []);
const keysOf = (v) => (isObject(v) ? Object.keys(v) : []);

module.exports = { isObject, entriesOf, keysOf };
