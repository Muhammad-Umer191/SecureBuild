// One flaw, one finding.
//
// The same bug is often published by several databases under different IDs:
//   GHSA-68w8-qjq3-2gfm (GitHub)   PYSEC-2021-98 (Python)   CVE-2021-33203 (MITRE)
// Each OSV record lists the others in `aliases`. Records that share any ID are
// grouped together (union-find), including chains: A lists B, B lists C.
const { isObject } = require('../common/objects');

// Union-find: each ID points towards a representative ("root") of its group.
function createUnionFind() {
  const parent = new Map();
  const find = (x) => {
    if (!parent.has(x)) parent.set(x, x);
    let root = x;
    while (parent.get(root) !== root) root = parent.get(root);
    let node = x;
    while (parent.get(node) !== root) {      // shorten the path for next time
      const next = parent.get(node);
      parent.set(node, root);
      node = next;
    }
    return root;
  };
  const union = (a, b) => parent.set(find(a), find(b));
  return { find, union };
}

const isGhsa = (id) => id.startsWith('GHSA-');
const byPreference = (a, b) => Number(isGhsa(b)) - Number(isGhsa(a)) || a.localeCompare(b);
const aliasesOf = (record) => (Array.isArray(record.aliases) ? record.aliases.filter((a) => typeof a === 'string') : []);

function summaryOf(records) {
  const ordered = [...records].sort((a, b) => byPreference(a.id, b.id));
  const withSummary = ordered.find((r) => typeof r.summary === 'string' && r.summary.trim());
  if (withSummary) return withSummary.summary.trim();
  const withDetails = ordered.find((r) => typeof r.details === 'string' && r.details.trim());
  if (withDetails) return withDetails.details.trim().split('\n')[0].slice(0, 200);
  return ordered[0].id;
}

function referencesOf(records) {
  const urls = [];
  for (const r of [...records].sort((a, b) => byPreference(a.id, b.id))) {
    for (const ref of Array.isArray(r.references) ? r.references : []) {
      if (isObject(ref) && typeof ref.url === 'string' && !urls.includes(ref.url)) urls.push(ref.url);
    }
  }
  return urls;
}

/**
 * @param {Object[]} records  OSV records affecting ONE package
 * @returns {{records: Object[], vulnIds: string[], cves: string[], summary: string, references: string[]}[]}
 */
function mergeAliases(records) {
  const uf = createUnionFind();
  for (const r of records) {
    uf.find(r.id);
    for (const alias of aliasesOf(r)) uf.union(alias, r.id);
  }

  const groups = new Map();
  for (const r of records) {
    const root = uf.find(r.id);
    if (!groups.has(root)) groups.set(root, []);
    groups.get(root).push(r);
  }

  return [...groups.values()].map((group) => {
    const recordIds = group.map((r) => r.id).sort(byPreference);
    const otherIds = [...new Set(group.flatMap(aliasesOf))]
      .filter((id) => !recordIds.includes(id))
      .sort((a, b) => Number(b.startsWith('CVE-')) - Number(a.startsWith('CVE-')) || a.localeCompare(b));
    const vulnIds = [...recordIds, ...otherIds];
    return {
      records: group,
      vulnIds,
      cves: vulnIds.filter((id) => id.startsWith('CVE-')),
      summary: summaryOf(group),
      references: referencesOf(group),
    };
  });
}

module.exports = { mergeAliases };
