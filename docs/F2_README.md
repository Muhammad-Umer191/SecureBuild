# F2: CVE fallback lookup, SBOM endpoints, drawer/SBOM wiring

F2 owns the finding detail drawer and the SBOM tab (frontend), and on the backend:
the cvelistV5 fallback lookup, the components (SBOM) endpoints, and the tests for them.
The findings list/detail/ignore endpoints are B1's (`/api/vulnerability/...`); F2 only
hooks the fallback lookup into the detail endpoint.

## Endpoints added

All need `Authorization: Bearer <token>` and only show the caller's own repos
(another user's repo or finding gets the same `404 NOT_FOUND` as a missing one).

| Method | Path | What |
|---|---|---|
| GET | `/api/cve/:cveId` | Fallback lookup: score, severity, vector, source, description and CWEs of one CVE from cvelistV5 (cached). 30 lookups/minute per user |
| GET | `/api/component/show/:repoId` | Components of the repo for the SBOM tab. Query: `ecosystem` (`npm,PyPI`), `direct`, `vulnerable` (`true`/`false`), `q`, `sort` (`name`/`vulns`/`ecosystem`), `order`, `page`, `limit` (max 200). Returns `{ scan, items, page, limit, total, summary }` |
| GET | `/api/component/export/:repoId?format=cyclonedx` | Downloads the SBOM as CycloneDX 1.5 JSON (`<owner>-<repo>-sbom.cdx.json`) |

Changed: `GET /api/vulnerability/:findingId` now fills `cves` (and the score, if OSV had
none) before answering.

Errors use the team format `{ error: { code, message } }`. New codes: `NO_SCAN` (404, repo
never scanned), `UPSTREAM_UNAVAILABLE` (502, cvelistV5 down), `RATE_LIMITED` (429).

## How the fallback lookup works

Code: `backend/src/services/cve/`.

1. B2's scanner gets advisories from OSV. Most have a CVSS vector; some only have a CVE alias.
   Those findings are saved with `score: null`, `severity: 'unknown'`.
2. When a finding is opened, `enrichFinding()` takes its `cveIds` (max 5), checks each against
   `^CVE-\d{4}-\d{4,7}$`, and fetches the record from cvelistV5:
   `CVE-2024-4068` → `raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/4xxx/CVE-2024-4068.json`.
3. The score is taken from the CNA's container first, then from ADP containers (CISA-ADP),
   preferring CVSS 3.1 → 3.0 → 4.0 → 2.0. If there is no CVSS block but the CNA gave a word
   like "critical", that word becomes the severity.
4. If OSV had no score, the finding gets the best CVE score, `scoreSource: 'cvelistV5'` and the
   explanation *"Score 7.5 (CVSS 3.1) taken from the CVE record in cvelistV5 (fallback lookup);
   severity band high = 7.0-8.9"*. The component's `maxSeverity` / `vulnerabilityCount` in the
   SBOM are updated to match.
5. Every lookup is cached in MongoDB (`cvecaches`, 24 h; "not found" 1 h; a TTL index deletes old
   entries). Once a finding has its CVE details, opening it again makes no lookup at all.

If GitHub is unreachable the drawer still opens; that CVE shows `error: 'UPSTREAM_UNAVAILABLE'`
and the lookup is retried the next time the finding is opened.

**For B1 (optional):** to fill scores at scan time instead of on first view, call it from the
worker after findings are saved:

```js
const { enrichFinding } = require('../services/cve');
for (const f of await Finding.find({ repo: repo._id, score: null })) await enrichFinding(f);
```

## SBOM export

B2's `toCycloneDX()` takes a fresh `ScanResult`. The export endpoint rebuilds that shape from the
saved `Component` and `Finding` documents (`services/sbomExport.js`) and runs it through the same
exporter, so the file passes the official CycloneDX 1.5 schema (checked in the tests). Because
the database keeps only "direct or not", the dependency graph lists just repo → direct packages.
Ignored findings, ignore reasons and user ids are left out.

## Frontend wiring

`frontend/src/api/findings.js` and `components.js` now call the real routes:
`/vulnerability/filter/:repoId`, `/vulnerability/:id` (GET/PATCH), `/component/show/:repoId`,
`/component/export/:repoId`. Mongo documents are mapped to what the drawer expects (`_id` → `id`).
Fake-data mode (`VITE_USE_FAKE_API=true`) is unchanged.

## Security controls

| Threat | Control | Test |
|---|---|---|
| SSRF / path tricks through the CVE id | Strict id pattern (validator and service) before a URL is built; fixed https host; redirects refused; origin re-checked | `cveLookup.test.js`, `cveEndpoints.test.js` "rejects … without a lookup" |
| Slow or huge upstream answers | 5 s timeout, 2 MB cap (declared and streamed), bad JSON or a different CVE id refused | "a slow upstream times out", "oversized responses are refused" |
| Hammering GitHub | MongoDB cache, shared in-flight requests, 30 lookups/min per user | "rate-limits each user separately" |
| Reading another user's data | `ownsRepo` on component routes; ownership check before any lookup on findings | "another user's repo is a generic 404", "another user's finding stays hidden (no lookup either)" |
| NoSQL injection (`?ecosystem[$ne]=npm`) | Joi rejects non-strings and unknown values; filters are built server-side; search text is regex-escaped | "rejects or ignores bad query" |
| Leaking data in the export | No user ids or ignore reasons; ignored findings dropped | "leaves ignored findings (and their reasons) out" |
| Path tricks through ids in the browser | Ids are URL-encoded in the API client | `realApi.test.js` "encodes ids" |

## Tests

```bash
cd backend
npx jest tests/f2        # 87 tests, in-memory MongoDB, no network
cd ../frontend
npx vitest run src/api/realApi.test.js
```

## Known limitations

- cvelistV5 does not always have a CVSS score (it holds what the CNA and CISA-ADP published,
  not NVD's scores). Example: CVE-2021-44906 (minimist) only has a CISA SSVC decision, so its
  severity stays `unknown` and the drawer asks for manual review.
- The SBOM export always uses the latest scan (findings and components are stored per repo,
  not per scan).
