// Fake data in the exact shapes of docs/API_CONTRACT_F2.md. Used when VITE_USE_FAKE_API=true.
// NOTE: advisory ids/CVEs are realistic but descriptions are paraphrased demo text, and the
// "unknown" finding is a made-up demo record. Do not treat this as real vulnerability data.

export const THRESHOLDS = { critical: 9.0, high: 7.0, medium: 4.0, low: 0.1 };

export function severityFromScore(score) {
  if (score === null || score === undefined) return 'unknown';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score >= 0.1) return 'low';
  return 'none';
}

export const fid = (n) => `6651${n.toString(16).padStart(20, '0')}`;
export const cid = (n) => `6652${n.toString(16).padStart(20, '0')}`;

export const SCAN = { id: '6650a1b2c3d4e5f600000001', finishedAt: '2026-11-10T09:12:00.000Z', commitSha: 'a1b2c3d' };

const cveUrl = (id) => `https://www.cve.org/CVERecord?id=${id}`;
const cve = (cveId, score, cvssVersion, vector, source, description, published) => ({
  cveId, state: 'PUBLISHED', score, severity: severityFromScore(score), cvssVersion, vector, source, description, published, url: cveUrl(cveId),
});

// CVE records as returned inside finding.cves[]
const CVES = {
  'CVE-2022-24999': cve('CVE-2022-24999', 7.5, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 'CISA-ADP',
    'qs before 6.10.3, as used in Express before 4.17.3 and other products, allows attackers to cause a Node process hang because an __proto__ key can be used. An unauthenticated remote attacker can place the payload in the query string of the URL.', '2022-11-26T00:00:00.000Z'),
  'CVE-2019-10744': cve('CVE-2019-10744', 9.1, '3.0', 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H', 'CISA-ADP',
    'Versions of lodash lower than 4.17.12 are vulnerable to Prototype Pollution. The function defaultsDeep could be tricked into adding or modifying properties of Object.prototype using a constructor payload.', '2019-07-26T00:00:00.000Z'),
  'CVE-2020-8203': cve('CVE-2020-8203', 7.4, '3.1', 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H', 'CISA-ADP',
    'Prototype pollution attack when using _.zipObjectDeep in lodash before 4.17.20.', '2020-07-15T00:00:00.000Z'),
  'CVE-2020-7598': cve('CVE-2020-7598', 5.6, '3.1', 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L', 'CISA-ADP',
    'minimist before 1.2.2 could be tricked into adding or modifying properties of Object.prototype using a constructor or __proto__ payload.', '2020-03-11T00:00:00.000Z'),
  'CVE-2022-23539': cve('CVE-2022-23539', 8.1, '3.1', 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', 'GitHub, Inc.',
    'Versions of the jsonwebtoken library before 9.0.0 could be misconfigured so that legacy, insecure key types are used for signature validation.', '2022-12-22T00:00:00.000Z'),
  'CVE-2021-33503': cve('CVE-2021-33503', 7.5, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 'CISA-ADP',
    'urllib3 before 1.26.5: a URL with many @ characters in the authority component causes catastrophic regular-expression backtracking, leading to denial of service.', '2021-06-29T00:00:00.000Z'),
  'CVE-2023-43804': cve('CVE-2023-43804', 8.1, '3.1', 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', 'GitHub, Inc.',
    'urllib3 does not strip the Cookie HTTP header on cross-origin redirects when the header is set manually, which can leak cookies to a different origin.', '2023-10-04T00:00:00.000Z'),
  'CVE-2023-32681': cve('CVE-2023-32681', 6.1, '3.1', 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N', 'GitHub, Inc.',
    'Since Requests 2.3.0, Proxy-Authorization headers are leaked to destination servers when redirected to an HTTPS endpoint. Fixed in 2.31.0.', '2023-05-22T00:00:00.000Z'),
  'CVE-2021-35042': cve('CVE-2021-35042', 9.8, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CISA-ADP',
    'Django 3.1.x before 3.1.13 and 3.2.x before 3.2.5 allows QuerySet.order_by SQL injection if order_by is untrusted input from a client of a web application.', '2021-07-02T00:00:00.000Z'),
  'CVE-2020-14343': cve('CVE-2020-14343', 9.8, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CISA-ADP',
    'PyYAML before 5.4 is susceptible to arbitrary code execution when it processes untrusted YAML files through the full_load method or with the FullLoader loader.', '2021-02-09T00:00:00.000Z'),
  'CVE-2020-28493': { cveId: 'CVE-2020-28493', error: 'UPSTREAM_UNAVAILABLE' },
};

const ref = (type, url) => ({ type, url });
const F = (n, o) => ({ id: fid(n), status: 'open', ignore: null, ...o });
const pkg = (name, version, ecosystem) => ({
  name, version, ecosystem,
  purl: ecosystem === 'PyPI' ? `pkg:pypi/${name.toLowerCase()}@${version}` : `pkg:npm/${name}@${version}`,
});

const RAW = [
  F(1, {
    vulnId: 'GHSA-hrpp-h998-j3pp', aliases: ['CVE-2022-24999'], cveIds: ['CVE-2022-24999'],
    summary: 'qs vulnerable to Prototype Pollution',
    details: 'qs before 6.10.3 allows attackers to cause a Node process hang because an `__proto__` key can be used.\n\n### Impact\nAn unauthenticated remote attacker can place the payload in the query string of a URL.\n\n### Patches\nUpgrade to 6.2.4, 6.3.3, 6.4.1, 6.5.3, 6.6.1, 6.7.3, 6.8.3, 6.9.7 or 6.10.3.',
    package: pkg('qs', '6.5.2', 'npm'), direct: false,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', score: 7.5, scoreSource: 'osv',
    fixedVersions: ['6.2.4', '6.10.3'], recommendedFix: '6.10.3',
    dependencyPath: ['express@4.17.1', 'body-parser@1.19.0', 'qs@6.5.2'],
    references: [ref('ADVISORY', 'https://github.com/advisories/GHSA-hrpp-h998-j3pp'), ref('WEB', 'https://nvd.nist.gov/vuln/detail/CVE-2022-24999'), ref('FIX', 'https://github.com/ljharb/qs/pull/428')],
    cwes: ['CWE-1321'], published: '2022-11-26T00:00:00.000Z', modified: '2024-01-02T00:00:00.000Z', firstSeenAt: '2026-11-01T10:00:00.000Z',
  }),
  F(2, {
    vulnId: 'GHSA-jf85-cpcp-j695', aliases: ['CVE-2019-10744'], cveIds: ['CVE-2019-10744'],
    summary: 'Prototype Pollution in lodash',
    details: 'Versions of lodash before 4.17.12 are vulnerable to Prototype Pollution.\n\nThe function `defaultsDeep` could be tricked into adding or modifying properties of `Object.prototype` using a `constructor` payload.',
    package: pkg('lodash', '4.17.11', 'npm'), direct: true,
    cvssVector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H', score: 9.1, scoreSource: 'osv',
    fixedVersions: ['4.17.12'], recommendedFix: '4.17.12', dependencyPath: ['lodash@4.17.11'],
    references: [ref('ADVISORY', 'https://github.com/advisories/GHSA-jf85-cpcp-j695'), ref('WEB', 'https://snyk.io/vuln/SNYK-JS-LODASH-450202')],
    cwes: ['CWE-1321', 'CWE-20'], published: '2019-07-26T00:00:00.000Z', modified: '2023-09-11T00:00:00.000Z', firstSeenAt: '2026-11-01T10:00:00.000Z',
  }),
  F(3, {
    vulnId: 'GHSA-vh95-rmgr-6w4m', aliases: ['CVE-2020-7598'], cveIds: ['CVE-2020-7598'],
    summary: 'Prototype Pollution in minimist',
    details: 'minimist before 1.2.2 could be tricked into adding or modifying properties of `Object.prototype` using a `constructor` or `__proto__` payload.',
    package: pkg('minimist', '1.2.0', 'npm'), direct: false,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L', score: 5.6, scoreSource: 'osv',
    fixedVersions: ['0.2.1', '1.2.2'], recommendedFix: '1.2.2', dependencyPath: ['mkdirp@0.5.1', 'minimist@1.2.0'],
    references: [ref('ADVISORY', 'https://github.com/advisories/GHSA-vh95-rmgr-6w4m'), ref('WEB', 'https://github.com/substack/minimist/commit/63e7ed05')],
    cwes: ['CWE-1321'], published: '2020-03-11T00:00:00.000Z', modified: '2023-01-09T00:00:00.000Z', firstSeenAt: '2026-11-01T10:00:00.000Z',
  }),
  F(4, {
    vulnId: 'GHSA-8cf7-32gw-wr33', aliases: ['CVE-2022-23539'], cveIds: ['CVE-2022-23539'],
    summary: 'jsonwebtoken unrestricted key type could lead to legacy keys usage',
    details: 'Versions before 9.0.0 of jsonwebtoken allow insecure key types to be used for signature verification.\n\nUpgrade to 9.0.0 or later.',
    package: pkg('jsonwebtoken', '8.5.1', 'npm'), direct: true,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', score: 8.1, scoreSource: 'osv',
    fixedVersions: ['9.0.0'], recommendedFix: '9.0.0', dependencyPath: ['jsonwebtoken@8.5.1'],
    // The javascript: URL is deliberate demo data to show unsafe links are not rendered as links.
    references: [ref('ADVISORY', 'https://github.com/advisories/GHSA-8cf7-32gw-wr33'), ref('WEB', 'javascript:alert(1)'), ref('FIX', 'https://github.com/auth0/node-jsonwebtoken/commit/e1fa9dcc')],
    cwes: ['CWE-327'], published: '2022-12-22T00:00:00.000Z', modified: '2023-11-07T00:00:00.000Z', firstSeenAt: '2026-11-02T08:30:00.000Z',
  }),
  F(5, {
    vulnId: 'GHSA-q2q7-5pp4-w6pg', aliases: ['CVE-2021-33503', 'PYSEC-2021-108'], cveIds: ['CVE-2021-33503'],
    summary: 'Catastrophic backtracking in URL authority parser when passed URL containing many @ characters',
    details: 'urllib3 before 1.26.5 is vulnerable to a denial of service: a URL with many `@` characters in the authority component causes catastrophic regular-expression backtracking.',
    package: pkg('urllib3', '1.26.4', 'PyPI'), direct: false,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', score: 7.5, scoreSource: 'osv',
    fixedVersions: ['1.26.5'], recommendedFix: '1.26.5', dependencyPath: ['requests@2.25.0', 'urllib3@1.26.4'],
    references: [ref('ADVISORY', 'https://github.com/advisories/GHSA-q2q7-5pp4-w6pg'), ref('FIX', 'https://github.com/urllib3/urllib3/commit/2d4a3fee')],
    cwes: ['CWE-400'], published: '2021-06-29T00:00:00.000Z', modified: '2023-06-13T00:00:00.000Z', firstSeenAt: '2026-11-01T10:00:00.000Z',
  }),
  F(6, {
    vulnId: 'GHSA-v845-jxx5-vc9f', aliases: ['CVE-2023-43804'], cveIds: ['CVE-2023-43804'],
    summary: 'urllib3 Cookie header not stripped on cross-origin redirects',
    details: 'urllib3 does not strip the `Cookie` HTTP header on cross-origin redirects when the header is set manually.\n\nUpgrade to 1.26.17 or 2.0.6.',
    package: pkg('urllib3', '1.26.4', 'PyPI'), direct: false,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', score: 8.1, scoreSource: 'osv',
    fixedVersions: ['1.26.17', '2.0.6'], recommendedFix: '1.26.17', dependencyPath: ['requests@2.25.0', 'urllib3@1.26.4'],
    references: [ref('ADVISORY', 'https://github.com/advisories/GHSA-v845-jxx5-vc9f')],
    cwes: ['CWE-200'], published: '2023-10-04T00:00:00.000Z', modified: '2024-02-01T00:00:00.000Z', firstSeenAt: '2026-11-01T10:00:00.000Z',
  }),
  F(7, {
    vulnId: 'GHSA-j8r2-6x86-q33q', aliases: ['CVE-2023-32681', 'PYSEC-2023-74'], cveIds: ['CVE-2023-32681'],
    summary: 'Unintended leak of Proxy-Authorization header in requests',
    details: 'Since Requests 2.3.0, `Proxy-Authorization` headers are leaked to destination servers when redirected to an HTTPS endpoint.\n\nUpgrade to 2.31.0.',
    package: pkg('requests', '2.25.0', 'PyPI'), direct: true,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N', score: 6.1, scoreSource: 'osv',
    fixedVersions: ['2.31.0'], recommendedFix: '2.31.0', dependencyPath: ['requests@2.25.0'],
    references: [ref('ADVISORY', 'https://github.com/advisories/GHSA-j8r2-6x86-q33q'), ref('FIX', 'https://github.com/psf/requests/commit/74ea7cf7')],
    cwes: ['CWE-200'], published: '2023-05-22T00:00:00.000Z', modified: '2024-01-15T00:00:00.000Z', firstSeenAt: '2026-11-01T10:00:00.000Z',
  }),
  F(8, {
    vulnId: 'GHSA-xpfp-f569-q3p2', aliases: ['CVE-2021-35042', 'PYSEC-2021-98'], cveIds: ['CVE-2021-35042'],
    summary: 'SQL injection in Django via QuerySet.order_by',
    details: 'Django 3.1.x before 3.1.13 and 3.2.x before 3.2.5 allows SQL injection if `QuerySet.order_by` receives untrusted input.\n\nUpgrade to 3.2.5 or later.',
    package: pkg('Django', '3.2.0', 'PyPI'), direct: true,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', score: 9.8, scoreSource: 'osv',
    fixedVersions: ['3.1.13', '3.2.5'], recommendedFix: '3.2.5', dependencyPath: ['Django@3.2.0'],
    references: [ref('ADVISORY', 'https://github.com/advisories/GHSA-xpfp-f569-q3p2'), ref('WEB', 'https://docs.djangoproject.com/en/3.2/releases/security/')],
    cwes: ['CWE-89'], published: '2021-07-02T00:00:00.000Z', modified: '2023-04-12T00:00:00.000Z', firstSeenAt: '2026-11-01T10:00:00.000Z',
  }),
  F(9, {
    vulnId: 'GHSA-8q59-q68h-6hv4', aliases: ['CVE-2020-14343', 'PYSEC-2021-142'], cveIds: ['CVE-2020-14343'],
    summary: 'Improper Input Validation in PyYAML',
    details: 'PyYAML before 5.4 is susceptible to arbitrary code execution when processing untrusted YAML through `full_load` or `FullLoader`.',
    package: pkg('PyYAML', '5.3.1', 'PyPI'), direct: false,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', score: 9.8, scoreSource: 'osv',
    fixedVersions: ['5.4'], recommendedFix: '5.4', dependencyPath: ['gunicorn@20.1.0', 'PyYAML@5.3.1'],
    references: [ref('ADVISORY', 'https://github.com/advisories/GHSA-8q59-q68h-6hv4')],
    cwes: ['CWE-20'], published: '2021-02-09T00:00:00.000Z', modified: '2023-08-03T00:00:00.000Z', firstSeenAt: '2026-11-01T10:00:00.000Z',
  }),
  F(10, {
    vulnId: 'GHSA-g3rq-g295-4j3m', aliases: ['CVE-2020-28493', 'PYSEC-2021-66'], cveIds: ['CVE-2020-28493'],
    summary: 'Regular Expression Denial of Service in Jinja2',
    details: 'The ReDoS vulnerability in the `urlize` filter of Jinja2 is mainly due to the sub-pattern in the URL regular expression. Fixed in 2.11.3.',
    package: pkg('Jinja2', '2.11.2', 'PyPI'), direct: false,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L', score: 5.3, scoreSource: 'osv',
    fixedVersions: ['2.11.3'], recommendedFix: '2.11.3', dependencyPath: ['Django@3.2.0', 'Jinja2@2.11.2'],
    references: [ref('ADVISORY', 'https://github.com/advisories/GHSA-g3rq-g295-4j3m')],
    cwes: ['CWE-400'], published: '2021-02-01T00:00:00.000Z', modified: '2023-03-30T00:00:00.000Z', firstSeenAt: '2026-11-03T12:00:00.000Z',
  }),
  F(11, {
    vulnId: 'GHSA-xx5q-3rfp-7m6w', aliases: [], cveIds: [],
    summary: 'Suspicious release of colors (advisory without CVSS score)',
    details: 'Demo record: this advisory has no CVSS vector and no linked CVE, so the severity is unknown.\n\nReview the release notes before upgrading.',
    package: pkg('colors', '1.4.1', 'npm'), direct: true,
    cvssVector: null, score: null, scoreSource: null,
    fixedVersions: [], recommendedFix: null, dependencyPath: ['colors@1.4.1'],
    references: [ref('ADVISORY', 'https://github.com/advisories/GHSA-xx5q-3rfp-7m6w')],
    cwes: [], published: '2022-01-10T00:00:00.000Z', modified: '2022-01-12T00:00:00.000Z', firstSeenAt: '2026-11-04T07:00:00.000Z',
  }),
  F(12, {
    vulnId: 'GHSA-p6mc-m468-83gw', aliases: ['CVE-2020-8203'], cveIds: ['CVE-2020-8203'],
    summary: 'Prototype Pollution in lodash (zipObjectDeep)',
    details: 'Prototype pollution attack when using `_.zipObjectDeep` in lodash before 4.17.20.',
    package: pkg('lodash', '4.17.11', 'npm'), direct: true,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H', score: 7.4, scoreSource: 'osv',
    fixedVersions: ['4.17.19'], recommendedFix: '4.17.19', dependencyPath: ['lodash@4.17.11'],
    references: [ref('ADVISORY', 'https://github.com/advisories/GHSA-p6mc-m468-83gw')],
    cwes: ['CWE-770', 'CWE-1321'], published: '2020-07-15T00:00:00.000Z', modified: '2024-01-12T00:00:00.000Z', firstSeenAt: '2026-11-01T10:00:00.000Z',
    status: 'ignored',
    ignore: { reason: 'Only used in unit tests, never shipped to production', by: '665000000000000000000a01', at: '2026-11-05T14:20:00.000Z' },
  }),
];

function explain(f) {
  if (f.score === null) {
    return 'No CVSS score found in the OSV advisory or in cvelistV5, so the severity is unknown. Review it manually.';
  }
  const bands = { critical: '9.0-10.0', high: '7.0-8.9', medium: '4.0-6.9', low: '0.1-3.9', none: '0.0' };
  const ver = f.cvssVector.slice(5, 8);
  const sev = severityFromScore(f.score);
  return `Score ${f.score} (CVSS ${ver}) taken from OSV advisory; severity band ${sev} = ${bands[sev]}`;
}

export function buildFindings() {
  return RAW.map((f) => ({
    ...f,
    ignore: f.ignore ? { ...f.ignore } : null,
    severity: severityFromScore(f.score),
    hasFix: f.fixedVersions.length > 0,
    cves: f.cveIds.map((id) => ({ ...CVES[id] })),
    scoring: { explanation: explain(f), thresholds: { ...THRESHOLDS } },
  }));
}

// [name, version, ecosystem, direct, licenses]
const COMPONENT_ROWS = [
  ['express', '4.17.1', 'npm', true, ['MIT']],
  ['body-parser', '1.19.0', 'npm', false, ['MIT']],
  ['qs', '6.5.2', 'npm', false, ['BSD-3-Clause']],
  ['lodash', '4.17.11', 'npm', true, ['MIT']],
  ['minimist', '1.2.0', 'npm', false, ['MIT']],
  ['mkdirp', '0.5.1', 'npm', false, ['MIT']],
  ['jsonwebtoken', '8.5.1', 'npm', true, ['MIT']],
  ['colors', '1.4.1', 'npm', true, ['MIT']],
  ['react', '18.2.0', 'npm', true, ['MIT']],
  ['react-dom', '18.2.0', 'npm', true, ['MIT']],
  ['scheduler', '0.23.0', 'npm', false, ['MIT']],
  ['loose-envify', '1.4.0', 'npm', false, ['MIT']],
  ['js-tokens', '4.0.0', 'npm', false, ['MIT']],
  ['debug', '2.6.9', 'npm', false, ['MIT']],
  ['ms', '2.0.0', 'npm', false, ['MIT']],
  ['accepts', '1.3.7', 'npm', false, ['MIT']],
  ['mime-types', '2.1.27', 'npm', false, ['MIT']],
  ['mime-db', '1.44.0', 'npm', false, ['MIT']],
  ['safe-buffer', '5.1.2', 'npm', false, ['MIT']],
  ['semver', '5.7.1', 'npm', false, ['ISC']],
  ['cookie', '0.4.0', 'npm', false, ['MIT']],
  ['bytes', '3.1.0', 'npm', false, ['MIT']],
  ['iconv-lite', '0.4.24', 'npm', false, ['MIT']],
  ['vite', '5.4.0', 'npm', true, ['MIT']],
  ['Django', '3.2.0', 'PyPI', true, ['BSD-3-Clause']],
  ['requests', '2.25.0', 'PyPI', true, ['Apache-2.0']],
  ['urllib3', '1.26.4', 'PyPI', false, ['MIT']],
  ['certifi', '2020.12.5', 'PyPI', false, ['MPL-2.0']],
  ['idna', '2.10', 'PyPI', false, ['BSD-3-Clause']],
  ['chardet', '4.0.0', 'PyPI', false, ['LGPL-2.1-or-later']],
  ['PyYAML', '5.3.1', 'PyPI', false, ['MIT']],
  ['Jinja2', '2.11.2', 'PyPI', false, ['BSD-3-Clause']],
  ['MarkupSafe', '1.1.1', 'PyPI', false, ['BSD-3-Clause']],
  ['sqlparse', '0.4.1', 'PyPI', false, ['BSD-3-Clause']],
  ['asgiref', '3.3.1', 'PyPI', false, ['BSD-3-Clause']],
  ['pytz', '2021.1', 'PyPI', false, ['MIT']],
  ['six', '1.15.0', 'PyPI', false, ['MIT']],
  ['gunicorn', '20.1.0', 'PyPI', true, ['MIT']],
  ['pytest', '7.4.0', 'PyPI', true, ['MIT']],
  ['pluggy', '1.0.0', 'PyPI', false, []],
];

export function buildBaseComponents() {
  return COMPONENT_ROWS.map(([name, version, ecosystem, direct, licenses], i) => ({
    id: cid(i + 1), name, version, ecosystem, purl: pkg(name, version, ecosystem).purl, direct, licenses,
  }));
}
