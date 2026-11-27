# SecureBuild Backend

Node.js + Express + MongoDB backend for **SecureBuild** — a supply-chain vulnerability scanner that clones public GitHub repositories, builds an SBOM, queries OSV.dev for known vulnerabilities, and serves findings through a JWT-protected REST API.

- **Scanner Pipeline** (clone, discover, parse, OSV lookup, CVSS scoring, CycloneDX export): see [`src/services/README.md`](src/services/README.md).
- Try a standalone CLI scan: `npm run scan -- https://github.com/OWASP/NodeGoat`

---

## Prerequisites

- **Node.js** `>= 18.0.0` and **npm**
- **MongoDB** (Community Server + `mongosh`) running locally at `mongodb://localhost:27017/securebuild`
- **Git** installed on `PATH` (used by the scanner to shallow-clone GitHub repositories)

---

## Step 1: Install System Dependencies (Node.js, Git, MongoDB)

Choose your operating system below.

### Ubuntu (22.04 / 24.04)

```bash
# 1. Update apt and install Git + curl
sudo apt update && sudo apt install -y git curl gnupg

# 2. Install Node.js (LTS via NodeSource)
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs

# 3. Install MongoDB Community Edition + mongosh
curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | \
  sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor

echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/8.0 multiverse" | \
  sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list

sudo apt update && sudo apt install -y mongodb-org

# 4. Enable & start MongoDB
sudo systemctl enable --now mongod
mongosh --eval "db.runCommand({ ping: 1 })"
```

### Arch Linux

```bash
# 1. Install Node.js, npm, and Git from official repos
sudo pacman -Syu --needed nodejs npm git base-devel

# 2. Install MongoDB & mongosh from AUR (using yay or paru)
# If you don't have yay installed:
#   git clone https://aur.archlinux.org/yay.git && cd yay && makepkg -si
yay -S --needed mongodb-bin mongodb-tools-bin mongosh-bin

# 3. Enable & start MongoDB
sudo systemctl enable --now mongodb
mongosh --eval "db.runCommand({ ping: 1 })"
```

### CachyOS

CachyOS is Arch-based and usually ships with `paru` pre-installed:

```bash
# 1. Install Node.js, npm, and Git
sudo pacman -Syu --needed nodejs npm git base-devel

# 2. Install MongoDB & mongosh from AUR (using paru, or yay if preferred)
paru -S --needed mongodb-bin mongodb-tools-bin mongosh-bin

# 3. Enable & start MongoDB
sudo systemctl enable --now mongodb
mongosh --eval "db.runCommand({ ping: 1 })"
```

> **Note (Arch / CachyOS vs Ubuntu):** On Ubuntu the systemd service is typically named `mongod`, whereas on Arch/CachyOS (`mongodb-bin`) it is named `mongodb`. If one says unit not found, use the other.

### Windows (10 / 11)

Open **PowerShell** (as Administrator for installs):

```powershell
# 1. Install Git, Node.js LTS, MongoDB Community Server, and mongosh via winget
winget install Git.Git
winget install OpenJS.NodeJS.LTS
winget install MongoDB.Server
winget install MongoDB.Shell

# 2. Restart your terminal so PATH updates take effect, then verify:
node -v
npm -v
git --version

# 3. Ensure MongoDB service is running
net start MongoDB
mongosh --eval "db.runCommand({ ping: 1 })"
```

*(Alternatively, download the installers directly from [nodejs.org](https://nodejs.org/), [git-scm.com](https://git-scm.com/), and [mongodb.com/try/download/community](https://www.mongodb.com/try/download/community).)*

---

## Step 2: Install Backend Packages

From the `backend` folder:

```bash
cd backend
npm install
```

> If you ever see `jest: command not found`, `node_modules` is not installed yet — run `npm install` (or `npm ci`) first.

---

## Step 3: Configure Environment Variables

Copy `.env.example` to `.env`:

- **Linux (Ubuntu / Arch / CachyOS):**
  ```bash
  cp .env.example .env
  ```
- **Windows (PowerShell):**
  ```powershell
  Copy-Item .env.example .env
  ```

Key variables in `.env`:
- `PORT=4000` — API server port
- `NODE_ENV=development` — environment (`development`, `test`, `production`)
- `MONGO_URI=mongodb://localhost:27017/securebuild` — MongoDB connection string
- `JWT_SECRET=...` — secret used to sign/verify JWT access tokens (change in production)
- `JWT_EXPIRES_IN=7d` — token lifetime
- `CLONE_TIMEOUT_MS=60000`, `CLONE_MAX_DEPTH=1`, `REPO_MAX_SIZE_MB=200` — repository clone limits
- `CORS_ORIGIN=http://localhost:5173` — allowed frontend origin

---

## Step 4: Initialize the MongoDB Database

Create the `securebuild` database, collections, and indexes from the Mongoose models:

```bash
npm run db:init
```

Verify the collections exist in MongoDB:

```bash
mongosh securebuild --eval "show collections"
```

Expected collections: `users`, `repos`, `scans`, `findings`, `components`.

---

## Step 5: Run the Backend Server

```bash
# Development (auto-reloads on file changes via nodemon)
npm run dev

# Production
npm start
```

Verify the API is up:

```bash
curl http://localhost:4000/api/health
# {"status":"ok"}
```

---

## Step 6: Run Tests

Tests use an isolated in-memory MongoDB via `mongodb-memory-server`.

### Linux (Ubuntu / Arch / CachyOS)

`package.json` points `mongodb-memory-server` to `/usr/bin/mongod` so it uses your local MongoDB binary directly:

```bash
# End-to-end suite (tests all endpoints with valid & invalid inputs and prints responses)
npm run test:e2e

# All endpoint tests (auth, scan, vulnerability, e2e)
npm run test:endpoints

# Scanner service unit tests
npm run test:services

# Full test suite (endpoints + services)
npm test
```

### Windows (PowerShell)

Because `package.json` uses Unix-style inline `VAR=val` syntax for Linux, run Jest directly on Windows (when online, `mongodb-memory-server` downloads/caches its Windows binary automatically):

```powershell
# Full test suite
npx jest --forceExit --detectOpenHandles

# Endpoint tests only
npx jest tests/endpoints --forceExit --detectOpenHandles --verbose

# End-to-end tests only
npx jest tests/endpoints/allEndpoints.test.js --forceExit --detectOpenHandles --verbose

# Scanner service unit tests
npx jest tests/services
```

*(If offline on Windows, point to your local `mongod.exe` first: `$env:MONGOMS_SYSTEM_BINARY="C:\Program Files\MongoDB\Server\8.0\bin\mongod.exe"`.)*

---

## Backend Structure & Overview

```text
backend/
├── jest.config.js               # Jest configuration (runs tests under tests/)
├── package.json
├── .env.example
├── src/
│   ├── app.js                   # Express app, security middleware (helmet, cors) & route mounting
│   ├── server.js                # Entry point (connects MongoDB & starts HTTP server on PORT)
│   ├── config/                  # Reads .env and exports DB + scanner config
│   ├── models/                  # Mongoose schemas: User, Repo, Scan, Finding, Component
│   ├── middleware/              # authenticate (JWT), validate (Joi), ownsRepo, errorHandler
│   ├── validators/              # Joi validation schemas for auth, scan, and vulnerability routes
│   ├── queries/                 # Database query helpers (authQueries, scanQueries, vulnerabilityQueries)
│   ├── controllers/             # Route handlers (authController, scanController, vulnerabilityController)
│   ├── routes/                  # Express routers mounted at /api/auth, /api/scan, /api/vulnerability
│   ├── services/
│   │   ├── scannerService.js    # Adapter bridging scan() pipeline -> MongoDB Finding/Component shapes
│   │   ├── scan/                # Pipeline orchestrator: clone -> discover -> parse -> osv -> findings
│   │   ├── clone/               # Shallow GitHub clone with size/timeout limits
│   │   ├── discovery/           # Finds package manifests and lockfiles
│   │   ├── parsers/             # Lockfile & manifest parsers (npm, PyPI) -> normalized SBOM
│   │   ├── osv/                 # Batch OSV.dev advisory lookup & caching
│   │   ├── findings/            # Alias merging, CVSS scoring, recommended fix versions
│   │   ├── ecosystems/          # npm & PyPI version/naming rules
│   │   └── cyclonedx/           # CycloneDX 1.5 SBOM export
│   ├── worker/
│   │   ├── index.js             # Background job dispatcher using child_process.fork() (no Redis needed)
│   │   └── scanWorker.js        # Child process that runs scannerService and updates MongoDB
│   ├── scripts/
│   │   └── initDb.js            # Initializes MongoDB collections & indexes
│   └── utils/                   # ApiError & Winston logger
└── tests/
    ├── setup.js                 # Isolated MongoMemoryServer setup for endpoint tests
    ├── endpoints/               # API endpoint & E2E integration tests
    └── services/                # Scanner pipeline unit tests
```

---

## API Endpoints

All endpoints except `/api/health`, `/api/auth/register`, and `/api/auth/login` require a valid JWT in the header:
`Authorization: Bearer <token>`

### Health
- `GET /api/health` — API health check

### Auth (`/api/auth`)
- `POST /api/auth/register` — Register a new user (`{ name, email, password }`)
- `POST /api/auth/login` — Authenticate and receive a JWT (`{ email, password }`)
- `GET /api/auth/me` — Get current authenticated user profile
- `POST /api/auth/changePassword` — Change password (`{ currentPassword, newPassword }`)

### Scan (`/api/scan`)
- `POST /api/scan/addRepo` — Add a GitHub repository (`{ url: "https://github.com/owner/repo" }`) and trigger a background scan
- `GET /api/scan/fetchRepos` — List all repositories for the authenticated user
- `POST /api/scan/refreshRepo/:repoId` — Trigger a background refresh scan to fetch new commits and update vulnerabilities

### Vulnerability (`/api/vulnerability`)
- `GET /api/vulnerability/show/:repoId` — List all vulnerabilities (open + ignored) for a repository
- `GET /api/vulnerability/filter/:repoId` — Filter vulnerabilities by `status`, `severity`, `ecosystem`, `hasFix`, `direct`, `q`, `sort`, `order`, `page`, `limit`
- `GET /api/vulnerability/:findingId` — Get full details for a single vulnerability
- `PATCH /api/vulnerability/:findingId` — Update status to `ignored` (requires `reason` >= 5 chars) or `open`

