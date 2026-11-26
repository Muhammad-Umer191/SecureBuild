// Cache for OSV advisory records, so repeat scans only download advisories
// that are new or changed. Keys include the advisory's `modified` time, so an
// updated advisory is a new key and gets fetched again.
//
// Any object with async get(key) / set(key, value) works. This default keeps
// records in memory for the life of the process; a Mongo-backed cache can be
// passed in later without changing the OSV code.

/**
 * In-memory cache. When full, the oldest entry is dropped first.
 * @param {{maxEntries?: number}} [opts]
 */
function createMemoryCache({ maxEntries = 20_000 } = {}) {
  const map = new Map();
  return {
    async get(key) {
      return map.has(key) ? map.get(key) : undefined;
    },
    async set(key, value) {
      if (map.has(key)) map.delete(key);
      map.set(key, value);
      if (map.size > maxEntries) map.delete(map.keys().next().value);
    },
    get size() {
      return map.size;
    },
  };
}

module.exports = { createMemoryCache };
