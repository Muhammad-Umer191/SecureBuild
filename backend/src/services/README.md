# SecureBuild scanner

This folder is the detection engine. Give it a public GitHub repository URL
and it tells you:

- **which packages the project uses** (the SBOM), and
- **which known vulnerabilities affect them**, how bad each one is, and which
  version to upgrade to.

It has no Express, Mongo or queue code. The backend calls one function,
`scan(url)`, and stores or serves the result.

---

## Quick start

Run these from `backend/`:

```bash
npm run scan -- https://github.com/OWASP/NodeGoat                 # full scan, printed summary
npm run scan -- https://github.com/OWASP/NodeGoat --show 30       # show more findings
npm run scan -- <url> --json result.json                          # save the full ScanResult
npm run scan -- <url> --cyclonedx sbom.cdx.json                   # save a CycloneDX 1.5 SBOM

npm run test:services     # all scanner tests, offline (no internet needed)
npm run test:network      # the same, plus tests against the real GitHub and OSV.dev
```

To check one stage on its own:

```bash
npm run try:clone    -- <url>    # clone only: size, commit, cleanup
npm run try:discover -- <url>    # which dependency files would be read
npm run try:parse    -- <url>    # the package list (SBOM) with purls
```

OWASP NodeGoat is a deliberately vulnerable app, so it makes a good demo:
1,091 packages, 311 findings, about 12 seconds.

---

## Key terms

| Term | Meaning |
|---|---|
| **Dependency** | A package the project uses. *Direct* = the project lists it itself. *Transitive* = pulled in by another package. Most vulnerabilities are in transitive ones. |
| **Dev dependency** | Only needed for development (tests, build tools). Still runs on developer and CI machines, so it is still scanned. |
| **Manifest** | `package.json`, `pyproject.toml`, `requirements.txt`. Lists direct dependencies with version *ranges* (`^4.17.0`). |
| **Lockfile** | `package-lock.json`, `poetry.lock`. Records the *exact* version of every installed package, direct and transitive. |
| **SBOM** | Software Bill of Materials: the full list of packages in a project. |
| **purl** | Package URL, a standard package ID: `pkg:npm/lodash@4.17.11`, `pkg:pypi/flask-login@0.6.2`. |
| **OSV.dev** | A free public vulnerability database that combines GitHub, the Python advisory DB and others. |
| **Advisory** | One published record about a flaw. One flaw can have several: `GHSA-...` (GitHub), `PYSEC-...` (Python), `CVE-...` (the global ID). These are *aliases*. |
| **MAL- advisory** | The package version is itself malware (a typosquat, a hijacked release). Always treated as CRITICAL. |
| **CVSS** | Common Vulnerability Scoring System. A vector like `CVSS:3.1/AV:N/AC:L/...` describes how a flaw can be exploited, and a formula turns it into a 0-10 score. |
| **Severity** | A label from the score: 9.0+ CRITICAL, 7.0+ HIGH, 4.0+ MEDIUM, above 0 LOW, 0 NONE, no data UNKNOWN. |
| **Affected range** | Versions where a flaw exists, as events: `introduced 0, fixed 4.17.12`. The `fixed` version is the upgrade target. |
| **semver / PEP 440** | Version-ordering rules for npm and Python. They differ (`2.0rc1` comes before `2.0` in Python), so each ecosystem has its own comparator. |
| **CycloneDX** | The industry-standard SBOM file format (OWASP) that other security tools import. |

---

## The pipeline

```
scan(url)
  1. clone       download the repo safely                    -> a temp folder + commit SHA
  2. discover    find the dependency files                   -> which files to read, and how
  3. parse       read them into the package list             -> Component[] (the SBOM)
                 (the clone is deleted here, before any network calls)
  4. osv         ask OSV.dev which advisories affect them    -> raw advisories per package
  5. findings    merge aliases, score, pick fix versions     -> Finding[] + Upgrade[]
                                                             -> ScanResult
toCycloneDX(result)                                          -> CycloneDX 1.5 JSON
```

Every stage is its own folder with an `index.js` "front door". Outside code
only imports from `index.js`; the other files are internals and can change.

---

## Using it from code

```js
const { scan } = require('./services/scan');
const { toCycloneDX } = require('./services/cyclonedx');

const result = await scan('https://github.com/OWASP/NodeGoat', {
  onProgress: (stage) => console.log('now:', stage),   // clone, discover, parse, osv, findings
});
const sbom = toCycloneDX(result);                       // plain object; JSON.stringify to save
```

### `scan(url, opts)` options (all optional)

| Option | Purpose |
|---|---|
| `clone` | `{ timeoutMs, maxSizeMb }`. Defaults come from `.env` (`CLONE_TIMEOUT_MS`, `REPO_MAX_SIZE_MB`). |
| `discovery` | e.g. `{ skipDirs: [] }` to also scan test and example folders |
| `cache` | OSV advisory cache `{ get, set }` (default: in memory, shared within the process) |
| `osvClient` | a custom OSV client (tests use a fake one) |
| `registry` | the ecosystem registry (default: npm + PyPI) |
| `onProgress(stage)` | called as each stage starts |
| `withClone` | replaces cloning (tests use a local folder) |

### `ScanResult`

```js
{
  repoUrl, commitSha, scannedAt,          // what was scanned, and when
  components: [Component],                // the SBOM
  findings:   [Finding],                  // worst first
  upgrades:   [Upgrade],                  // one per vulnerable package
  warnings:   [string],                   // from every stage, in pipeline order
  stats: { packages, vulnerablePackages, findings, fixable, bySeverity, durationMs },
}

Component = { name, version, ecosystem, purl, direct, dev, license, dependsOn: [purl], source, approximate }
Finding   = { purl, vulnIds, cves, summary, references, cvss: { v31?, v40? }, score, severity,
              fixedVersion, approximate }
Upgrade   = { purl, name, ecosystem, from, to, closes, unfixed, worstSeverity }
```

- **`approximate: true`** means the version was *estimated* from a manifest
  range, because there was no lockfile. Such findings may not apply.
- **`fixedVersion`** is the lowest version that fixes *that* flaw.
- **`Upgrade.to`** is the one version that fixes *all* of a package's flaws
  (e.g. lodash 4.17.11 -> 4.18.0 closes 6 findings).

The full type comments are in `scan/index.js`, `parsers/normalizeComponents.js`
and `findings/index.js`.

---

## The modules

### `clone/` - download the repo safely
The repo is untrusted input, so cloning is locked down:

- **URL check:** only `https://github.com/<owner>/<repo>` is accepted.
- **No shell:** git runs through `execFile` with an argument list, so text in
  the URL can't run as a command.
- **Minimal environment:** git gets no server secrets, no user or system git
  config, no saved credentials and no password prompts. Private repos are
  never reachable, even on a logged-in machine.
- **Locked-down clone:**
  - https only; hooks off; no submodules or Git LFS files;
  - symlinks are written as plain text files;
  - latest commit of the default branch only.
- **Limits:** a time limit and a size limit, checked while the clone runs.
- **Cleanup:** the temp folder is always deleted. `withClone()` guarantees it.

### `discovery/` - which files to read
Walks the clone (never follows symlinks; capped at 20 levels and 100,000
entries) and decides per folder:

- **Lockfiles** are always used: exact versions and the full tree.
- **Manifests** are used only as a fallback when no lockfile covers them. Their
  results are *approximate*.
  - **npm:** a `package-lock.json` in a parent folder covers sub-folders
    (workspaces). A `yarn.lock` / `pnpm-lock.yaml` (not readable yet) does the
    same, so a big monorepo gives one approximate source, not hundreds.
  - **PyPI:** a `poetry.lock` covers only its own folder.
- **Skipped folders:**
  - never entered: `node_modules`, `.git`, `vendor`, virtualenvs;
  - entered but skipped, with one count warning: test, fixture, example,
    playground and demo folders.
- **Size cap:** files over 20 MB are skipped.

### `ecosystems/` - everything npm- or Python-specific
One folder per ecosystem, each with a descriptor:

- which file names are its lockfiles, manifests and unsupported lockfiles;
- its `parse()` functions;
- name rules (`normalizeName`: Python's `Flask_Login` = `flask-login`);
- `purl()`;
- `compareVersions()` (semver for npm, PEP 440 for Python).

Discovery, parsers and findings contain no ecosystem names; they ask the
registry. See "Adding an ecosystem" below.

### `parsers/` - files to SBOM
For each file, `parseSources()` reads it safely (inside the clone only,
regular files only, at most 20 MB) and hands it to the ecosystem's parser.

- **npm `package-lock.json`** v1, v2 and v3. Dependencies are resolved the way
  Node loads them, so two versions of one package each link correctly.
- **`poetry.lock`**, with direct and dev flags from `pyproject.toml`.
- **Manifest fallback** (`package.json`, `pyproject.toml`, `requirements.txt`):
  direct dependencies only. Each version is the *lowest* the range allows,
  because that version is most likely to still have old bugs.

Then `normalizeComponents()` gives each package its purl and merges
duplicates:

- direct if any copy is direct;
- dev only if every copy is dev;
- approximate only if every copy is approximate.

A broken file is a warning; the other files still count.

### `osv/` - which advisories affect each package
1. **Batch query:** `POST /v1/querybatch`, up to 1,000 purls per request. It
   returns only advisory IDs, and follows paging when a package has many.
2. **Full records:** `GET /v1/vulns/{id}` for each unique ID, at most 8 at a
   time. Records are cached by ID + last-modified date, so a repeat scan only
   downloads new or changed advisories.

Other rules:

- **Retries:** network errors, timeouts, 429 and 5xx are retried with backoff
  (0.5s, 1s, 2s), honouring `Retry-After`.
- **Withdrawn advisories** are dropped.
- **Never a false "clean":** if OSV.dev stays unreachable, the scan *fails*. It
  never reports "no vulnerabilities".

### `findings/` - advisories to findings
- **Merge aliases** (union-find): records that share any ID are one flaw, one
  finding.
- **Score:** each CVSS vector is scored with `ae-cvss-calculator` (3.0, 3.1,
  4.0; checked against the Python `cvss` package). The highest score counts.
  - No vector: GitHub's label (`MODERATE` = MEDIUM).
  - Nothing at all: UNKNOWN.
  - **Malware (`MAL-`) is always CRITICAL** and listed first.
- **Fix version:**
  - find the affected range that contains *our installed version*, for *this
    package* (lodash, not lodash-es);
  - its `fixed` event is the fix; `last_affected` means no fix exists;
  - if alias records disagree, the higher fix is used (safe for both).
- **Upgrades:** per package, the highest fix closes all of its fixable
  findings.

### `scan/` - the entry point
Runs the stages in order, times them, and collects every warning.

- **Errors** keep their type and code, and get a `stage` label saying where
  they happened (see the table below).

### `cyclonedx/` - standard SBOM export
`toCycloneDX(result)` builds a CycloneDX 1.5 document:

- **metadata:** the repo and commit;
- **components:** purl, licence, dev = `scope: optional`;
- **dependencies:** the graph;
- **vulnerabilities:** one per flaw, with CVSS ratings, affected packages and
  fixes.

Licences become SPDX IDs where possible, otherwise expressions or free text.
Every test output is validated against the official schema in
`cyclonedx/schema/`.

### `common/` - small shared helpers
Safe object access, warning wording, purl building, `ParseError`. It has no
`index.js`: files import the exact helper they need.

---

## Errors

A scan either returns a `ScanResult` or throws. Every error has a `code`,
a `permanent` flag (`true` = retrying won't help) and a `stage`.

| Code | Stage | Permanent | Meaning |
|---|---|---|---|
| `INVALID_URL` | clone | yes | Not `https://github.com/<owner>/<repo>` |
| `REPO_NOT_FOUND` | clone | yes | Missing or private (GitHub answers the same for both) |
| `REPO_TOO_LARGE` | clone | yes | Over `REPO_MAX_SIZE_MB` |
| `CLONE_TIMEOUT` | clone | no | Over `CLONE_TIMEOUT_MS` |
| `NETWORK_ERROR` | clone | no | Couldn't reach GitHub |
| `GIT_NOT_INSTALLED`, `CLONE_FAILED` | clone | no | Anything else git reported |
| `OSV_UNAVAILABLE` | osv | no | OSV.dev failed after 4 attempts |
| `OSV_REJECTED` | osv | yes | OSV.dev refused the request (a bug on our side) |
| `OSV_BAD_RESPONSE` | osv | no | OSV.dev answered something unusable |

**Warnings** are different: they don't stop the scan. They explain what was
skipped or estimated, for example a missing lockfile, an unreadable file, git
dependencies, or advisories OSV no longer has. Show them to the user next to
the results.

---

## Adding an ecosystem

1. Create `ecosystems/<name>/index.js` exporting a descriptor:

   ```js
   module.exports = {
     ecosystem: 'Go',                                  // exactly as OSV.dev spells it
     lockfiles: [{ filename: 'go.sum', format: 'text', companion: 'go.mod', parse }],
     manifests: [{ filename: 'go.mod', format: 'text', parse: parseGoMod }],
     unsupportedLockfiles: [],
     lockfileScope: 'folder',                          // or 'subtree' for workspaces
     normalizeName: (name) => name,
     purl: (name, version) => `pkg:golang/${name}@${version}`,
     compareVersions: (a, b) => /* <0, 0, >0, or null if invalid */,
   };
   ```

   `parse(content, { source, companion, readFile })` returns
   `{ components, warnings }`. `content` arrives already read and decoded.
   Use `readFile` for any extra file, so the safety checks apply.

2. Add it to `DEFAULT_ECOSYSTEMS` in `ecosystems/index.js`.

That's all. Discovery, parsing, OSV, findings and CycloneDX pick it up without
changes. The registry checks the descriptor when it's created. The test
`tests/services/ecosystems/registry.test.js` registers a toy Go ecosystem
to prove this.

---

## Tests

```
backend/tests/services/
  clone/  discovery/  ecosystems/npm|pypi/  parsers/  osv/  findings/  scan/  cyclonedx/
  fixtures/        hand-written lockfiles and manifests
  osv/fixtures/    real OSV.dev responses (lodash, left-pad, @babel/traverse)
```

- **Offline by default:**
  - a fake clone uses a local folder;
  - a fake OSV.dev replays saved responses;
  - the network is never touched.
- **`npm run test:network`** also runs the tests marked `NETWORK_TESTS=1`:
  real clones from GitHub and real OSV.dev queries.
- **Expected values were worked out independently:** CVSS scores with the
  Python `cvss` package, fix versions by hand from the raw advisories, and
  CycloneDX against the official schema.

---

## Not supported yet

- `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock`: warned about. The project's
  `package.json` (or Python manifest) is used instead, as an approximate
  source.
- Private repositories and non-GitHub hosts.
- Reachability: whether your code actually calls the vulnerable function.
- Score fallback from MITRE's CVE list for findings with no CVSS data in OSV.
  Deferred until we measure how often it's needed.
