# SecureBuild Frontend — F1 Implementation Notes

This covers the F1 (Frontend Lead) layout, authentication, repository management, findings table, and scan history built on top of F2's `FindingDetailDrawer` and `SbomTab` components.

All F2 files (`FindingDetailDrawer.jsx`, `SbomTab.jsx`, `src/components/*`, `src/api/findings.js`, `src/api/components.js`) were left untouched to avoid merge conflicts.

---

## What Was Built

### 1. Login & Registration (`src/features/auth/LoginPage.jsx`)
- Sign in and Create account tabs in one form with basic client-side validation (required fields, minimum 8-character password on signup).
- Saves the returned JWT in `localStorage` under `sb_token` (which `src/api/client.js` automatically sends as `Authorization: Bearer <token>`).
- On page load, `App.jsx` calls `getMe()` to restore the session if a token is already saved.
- When `VITE_USE_FAKE_API=true`, quick-fill buttons for `Admin`, `Analyst`, and `Viewer` are shown so all roles can be tested easily (`viewer` is read-only).

### 2. App Shell & Repository Sidebar (`src/App.jsx`, `src/features/repos/AddRepoModal.jsx`)
- Replaced the temporary demo harness in `App.jsx` with the main layout:
  - **Sidebar:** Lists repositories, lets `admin`/`analyst` users add a repo via `AddRepoModal` (`https://github.com/owner/repo` validation matching `backend/src/models/Repo.js`), switch the active repo, and remove a repo with an inline `Yes / No` confirmation.
  - **Top bar:** Displays the active repository name/link, last scan timestamp and commit SHA, and a **Refresh** button that triggers a new scan (`POST /api/repos/:repoId/scans`) and reloads the active tab.
  - **Tabs:** `Findings`, `Ignored`, `SBOM` (`<SbomTab />`), and `History`.

### 3. Filterable Findings Table (`src/features/findings/FindingsTab.jsx`)
- Used for both the **Findings** (`status=open`) and **Ignored** (`status=ignored`) tabs.
- Displays summary cards at the top (Total + Critical/High/Medium/Low counts). Clicking a severity card toggles that severity filter.
- Supports debounced search (package name, GHSA ID, CVE ID), dropdown filters (Severity, Ecosystem, Fix status, Direct/Transitive), column sorting, pagination, and a reset button.
- Clicking any row opens F2's `<FindingDetailDrawer />`.

### 4. Scan History (`src/features/scans/ScanHistoryTab.jsx`)
- Lists past scan runs for the selected repository with status badges (`Completed`, `Failed`, `Running`, `Queued`), commit SHA, start/finish times, findings/components counts, and error messages for failed scans.

### 5. API Modules & Mock Mode (`src/api/`)
- Added `src/api/auth.js`, `src/api/repos.js`, and `src/api/scans.js` following the same `USE_FAKE_API` switch used by F2 in `findings.js` and `components.js`.
- Mock responses live in `src/api/fake/portal.js` and match `backend/src/models/` shapes.

---

## Backend Endpoints Expected (For Integration)

When `VITE_USE_FAKE_API=false`, the new frontend modules call these endpoints (under `/api`):

| Action | Method & Path | Request / Expected Response |
| :--- | :--- | :--- |
| Sign in | `POST /auth/login` | Body: `{ email, password }` -> `{ token, user }` |
| Sign up | `POST /auth/register` | Body: `{ name, email, password }` -> `{ token, user }` |
| Current user | `GET /auth/me` | `{ user }` (include `role`: `'admin' \| 'analyst' \| 'viewer'`) |
| List repos | `GET /repos` | `{ items: [...] }` or `[...]` |
| Add repo | `POST /repos` | Body: `{ url }` -> created repo object |
| Remove repo | `DELETE /repos/:repoId` | `200 OK` |
| Trigger scan | `POST /repos/:repoId/scans` | Created scan object |
| Scan history | `GET /repos/:repoId/scans` | `{ items: [...] }` or `[...]` |

---

## Running Locally

```bash
cd frontend
npm install
npm run dev     # runs in mock mode via .env.development.local (VITE_USE_FAKE_API=true)
npm run build   # production build check
npm test        # Vitest suite (requires Node >= 22.19.0 because of jsdom/undici)
```

Create `frontend/.env.development.local` (git-ignored) with `VITE_USE_FAKE_API=true` for mock mode, or `VITE_USE_FAKE_API=false` to connect to the live Express backend on port `4000`.
