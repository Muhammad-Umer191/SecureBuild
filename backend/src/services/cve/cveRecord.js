// Pure helpers for cvelistV5 records (CVE JSON 5.x). No network, no database.
// Record format: https://github.com/CVEProject/cve-schema

const CVE_ID_RE = /^CVE-(\d{4})-(\d{4,7})$/;

const {
  THRESHOLDS, SEVERITY_RANK, isValidScore, severityFromScore, normalizeSeverity,
} = require('../common/severity');

/**
 * Validate and normalise a CVE id. Returns null when invalid, so a request can be
 * rejected before any URL is built (no path traversal / SSRF through the id).
 */
function normalizeCveId(input) {
  if (typeof input !== 'string' || input.length > 20) return null;
  const id = input.trim().toUpperCase();
  const m = CVE_ID_RE.exec(id);
  if (!m) return null;
  const year = Number(m[1]);
  if (year < 1999 || year > 2100) return null;
  return id;
}

/**
 * cvelistV5 layout: cves/<year>/<number / 1000>xxx/<id>.json
 *   CVE-2021-44228 -> 2021/44xxx/CVE-2021-44228.json
 *   CVE-2024-0001  -> 2024/0xxx/CVE-2024-0001.json
 */
function cveRecordPath(cveId) {
  const m = CVE_ID_RE.exec(cveId);
  if (!m) throw new Error('Invalid CVE id');
  return `${m[1]}/${Math.floor(Number(m[2]) / 1000)}xxx/${cveId}.json`;
}

// Best CVSS block first.
const CVSS_KEYS = [
  ['cvssV3_1', '3.1'],
  ['cvssV3_0', '3.0'],
  ['cvssV4_0', '4.0'],
  ['cvssV2_0', '2.0'],
];

function pickCvss(metrics) {
  if (!Array.isArray(metrics)) return null;
  for (const [key, version] of CVSS_KEYS) {
    for (const m of metrics) {
      const block = m && m[key];
      if (block && isValidScore(block.baseScore)) {
        return {
          score: block.baseScore,
          severity: normalizeSeverity(block.baseSeverity) || severityFromScore(block.baseScore, version),
          vector: typeof block.vectorString === 'string' ? block.vectorString.slice(0, 200) : null,
          cvssVersion: version,
        };
      }
    }
  }
  return null;
}

// Some CNAs publish only a word: { other: { type: "unknown", content: { other: "critical" } } }
function pickTextSeverity(metrics) {
  if (!Array.isArray(metrics)) return null;
  for (const m of metrics) {
    const c = m && m.other && m.other.content;
    if (!c) continue;
    for (const candidate of [c.other, c.text, c.value, c.severity]) {
      const sev = normalizeSeverity(candidate);
      if (sev) return sev;
    }
  }
  return null;
}

function providerName(container, fallback) {
  const short = container && container.providerMetadata && container.providerMetadata.shortName;
  return typeof short === 'string' && short ? short.slice(0, 50) : fallback;
}

function englishText(list) {
  if (!Array.isArray(list) || !list.length) return null;
  const en = list.find((d) => d && typeof d.lang === 'string' && d.lang.toLowerCase().startsWith('en'));
  const value = (en || list[0]).value;
  return typeof value === 'string' ? value.slice(0, 2000) : null;
}

function collectCwes(containers) {
  const out = new Set();
  for (const c of containers) {
    for (const pt of (c && Array.isArray(c.problemTypes) ? c.problemTypes : [])) {
      for (const d of (Array.isArray(pt.descriptions) ? pt.descriptions : [])) {
        const id = typeof d.cweId === 'string' ? d.cweId : (/CWE-\d+/.exec(d.description || '') || [])[0];
        if (id && /^CWE-\d{1,5}$/.test(id)) out.add(id);
      }
    }
  }
  return [...out].slice(0, 20);
}

function isoOrNull(value) {
  if (typeof value !== 'string') return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

class CveRecordError extends Error {}

/**
 * Raw CVE JSON 5 record -> the small object the API returns.
 * Score: CNA container first, then ADP containers (CISA-ADP "Vulnrichment"),
 * and inside each one CVSS 3.1 -> 3.0 -> 4.0 -> 2.0.
 */
function parseCveRecord(record, expectedId) {
  if (!record || typeof record !== 'object' || record.dataType !== 'CVE_RECORD') {
    throw new CveRecordError('Not a CVE JSON 5 record');
  }
  const meta = record.cveMetadata || {};
  const cveId = normalizeCveId(meta.cveId);
  if (!cveId || (expectedId && cveId !== expectedId)) {
    throw new CveRecordError('CVE id in record does not match the request');
  }
  const state = meta.state === 'REJECTED' ? 'REJECTED' : 'PUBLISHED';
  const containers = record.containers || {};
  const cna = containers.cna || {};
  const adps = Array.isArray(containers.adp) ? containers.adp : [];

  let cvss = null;
  let source = null;
  if (state === 'PUBLISHED') {
    for (const [container, fallback] of [[cna, 'CNA'], ...adps.map((a) => [a, 'ADP'])]) {
      cvss = pickCvss(container && container.metrics);
      if (cvss) {
        source = providerName(container, fallback);
        break;
      }
    }
  }

  let severity = cvss ? cvss.severity : 'unknown';
  if (!cvss && state === 'PUBLISHED') {
    const text = pickTextSeverity(cna.metrics);
    if (text) {
      severity = text;
      source = providerName(cna, 'CNA');
    }
  }

  return {
    cveId,
    state,
    score: cvss ? cvss.score : null,
    severity,
    cvssVersion: cvss ? cvss.cvssVersion : null,
    vector: cvss ? cvss.vector : null,
    source,
    // Rejected records carry rejectedReasons instead of descriptions.
    description: englishText(cna.descriptions) || englishText(cna.rejectedReasons),
    cwes: collectCwes([cna, ...adps]),
    published: isoOrNull(meta.datePublished),
    updated: isoOrNull(meta.dateUpdated),
    url: `https://www.cve.org/CVERecord?id=${cveId}`,
  };
}

module.exports = {
  THRESHOLDS,
  SEVERITY_RANK,
  isValidScore,
  severityFromScore,
  normalizeSeverity,
  normalizeCveId,
  cveRecordPath,
  parseCveRecord,
  CveRecordError,
};
