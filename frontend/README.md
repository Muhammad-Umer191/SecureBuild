# SecureBuild Frontend

## F2: finding detail drawer and SBOM tab

- `src/features/findings/FindingDetailDrawer.jsx`: score with readable CVSS vector, why that score, fix version with a copyable upgrade command, dependency path, linked CVEs, references, ignore / re-open (hidden for viewers)
- `src/features/sbom/SbomTab.jsx`: summary cards, search and filters, sortable component table, CycloneDX export
- `src/api/`: API client with a fake-data mode (`VITE_USE_FAKE_API=true` in `.env.development`) so the screens work before the backend is ready
- `src/App.jsx` is only a demo harness for these two pieces; F1 owns the real layout

```bash
npm install
npm run dev     # http://localhost:5173
npm test        # 66 tests
```

When the backend is running, set `VITE_USE_FAKE_API=false` in `.env.development.local` (git-ignored); `/api` is proxied to `http://localhost:4000`.
