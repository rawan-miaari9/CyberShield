# CyberShield — Vulnerability Management Platform

CyberShield is a vulnerability management and orchestration platform for security teams.
It takes raw scanner output and turns it into a managed workflow: analyst review, risk
assessment, assignment, remediation tracking, verification, audit, and AI-assisted guidance.

**OWASP ZAP is the external scanning engine.** CyberShield does not scan anything itself —
it asks ZAP (running separately) to crawl registered web applications through the ZAP API,
then synchronizes ZAP's alerts as findings for analyst review. Likewise, AI guidance is
produced server-side through the Google Gemini API; the frontend never contacts AI or
scanner services directly.

## Problem CyberShield Solves

Vulnerability scanners output hundreds of raw, duplicated, unprioritized alerts. Without a
management layer, teams struggle to answer: *which findings are real, how severe is each
one in our context, who is fixing it, and is the fix verified?* CyberShield closes that gap
with a single review → assess → assign → remediate → verify → close pipeline, backed by
notifications and a complete audit trail.

## Key Features

- **ZAP integration** — test connection, spider-based Scan Website with progress tracking,
  and Sync Findings import with normalization and fingerprint deduplication.
- **Finding review workflow** — NEW → REVIEWED → PROMOTED (terminal) / DISMISSED, with
  duplicate promotion blocked.
- **Vulnerability lifecycle** — NEW → ASSIGNED → IN_PROGRESS → REMEDIATED → VERIFIED → CLOSED,
  strictly one forward step at a time, with linked remediation tasks synchronized server-side.
- **Risk assessment** — analyst-selected Impact × Likelihood scoring with automatic levels.
- **Remediation tracking** — tasks derived from the vulnerability lifecycle, notes/evidence,
  due dates, and analyst verification.
- **AI Security Assistant** — server-side Gemini guidance (explanation, impact, remediation
  and verification steps) with append-only per-vulnerability history.
- **Asset management** — inventory (type, URL/hostname/IP, criticality) with analyst-only
  create/edit and protected-delete handling for assets with security history.
- **Notifications & audit trail** — per-user notifications with analyst overview, and a
  read-only, role-gated audit log of every workflow action.

## Architecture

```
React (Vite + TypeScript + Tailwind)
   │  HTTPS/JSON, JWT
   ▼
Django REST Framework  ──►  PostgreSQL (dev: SQLite file)
   │  server-side only
   ├─► OWASP ZAP API (external scanner, runs separately)
   └─► Google Gemini API (AI guidance, backend key only)
```

The React frontend talks only to the Django API. Django orchestrates both external
services: it drives ZAP scans and alert imports, and it calls Gemini with a safe,
server-built vulnerability context. API keys live exclusively in backend environment
variables.

## Technology Stack

- **Frontend** — React 19, TypeScript, Vite 6, React Router 7, Tailwind CSS 4, Axios, Recharts.
- **Backend** — Django, Django REST Framework, SimpleJWT, django-cors-headers,
  `dj-database-url`, `psycopg` (PostgreSQL), `requests` (ZAP), `google-genai` + `pydantic` (AI).
- **Database** — configured via `DATABASE_URL` (SQLite file for local dev, PostgreSQL-capable).
- **External services** — OWASP ZAP (separate instance), Google Gemini API.

## User Roles & RBAC

| Capability | Administrator | Security Analyst | IT / Developer |
|---|---|---|---|
| Review / promote findings | ✓ | ✓ | — |
| Assess risk, assign, set due dates | ✓ | ✓ | — |
| Start progress / mark remediated (own items) | ✓ | ✓ | Own assigned only |
| Verify remediation / close | ✓ | ✓ | — |
| Manage assets, run ZAP scan/sync | ✓ | ✓ | — |
| Generate AI guidance | ✓ | ✓ | Only for assigned vulns |
| View AI history, notifications | ✓ | ✓ (all rows) | Own rows |
| Audit logs | ✓ | ✓ | — |

Backend endpoints enforce every rule above (403 otherwise); the UI mirrors them for usability
but is never the authority. Roles are stored as `Role` rows linked through `UserProfile`.

## Vulnerability Management Workflow

1. ZAP alerts sync in as **Findings** (`NEW`), deduplicated by fingerprint.
2. Analyst marks a finding **REVIEWED** (or **DISMISSED**); valid findings are **PROMOTED**
   into vulnerabilities (promotion is terminal for the finding and cannot repeat).
3. Promotion requires analyst-selected **Impact** and **Likelihood** (1–5 each).
4. The vulnerability is **ASSIGNED** to a developer, who moves it **IN_PROGRESS** →
   **REMEDIATED** (one click advances the linked remediation task server-side).
5. An analyst **VERIFIES** (completing the remediation task), then **CLOSES**.
6. Every step writes audit entries and notifies whoever must act next (never the actor).

## Risk Assessment

- **Scanner Severity** = severity imported from the external scanner (informational only).
- **Impact** = analyst assessment, 1–5. **Likelihood** = analyst assessment, 1–5.
- **Risk Score = Impact × Likelihood** (recomputed server-side on save).
- **Risk Level**: Low 1–4 · Medium 5–9 · High 10–16 · Critical 17–25.

## OWASP ZAP Integration

Current MVP workflow (Findings page):

1. Select a registered asset → **Test Connection**.
2. **Scan Website** → CyberShield asks ZAP to **crawl** the target (Spider).
3. Track progress (polled ~every 2–3 s) → at 100%, **Sync Findings**.
4. Sync applies `baseurl` filtering, severity normalization, and **fingerprint deduplication**
   (SHA-256 over stable scanner properties such as plugin ID, URL, parameter, and method),
   importing only genuinely new alerts as `NEW` findings.

Important truths for this MVP:

- ZAP performs **Spider crawling + passive scanning observations**, not a full ZAP Active Scan.
- **CyberShield never accepts an arbitrary scan URL.** The scan endpoint takes only
  `{asset_id}`; the backend loads the registered `Asset` and derives the target strictly
  from `asset.url` (400 if missing, 404 if unknown).
- Results are never auto-imported: synchronization is always an explicit analyst action.
- ZAP must be running and reachable by Django (local daemon or, for deployment, a
  private/headless service or container — not yet part of this repository).

## AI Security Assistant

Explicit-click, server-side Gemini guidance per vulnerability, persisted as append-only
`AIAnalysis` history (reload-safe, never overwritten). Each analysis contains:

- **Explanation** — what the weakness is.
- **Potential Impact** — what exploitation could cause.
- **Remediation Steps** — how to fix it.
- **Verification Steps** — how to confirm the fix.

Guidance is **advisory and human-reviewed**. The Gemini API key stays backend-side; only a
safe vulnerability context (title, description, severity, impact/likelihood) is sent —
never secrets, credentials, or raw scanner evidence. Generation RBAC: Administrator /
Security Analyst always; IT/Developer only for vulnerabilities assigned to them.

## Asset Management

Inventory with name, type (`WEB_APP` / `SERVER` / `NETWORK_DEVICE` / `OTHER`), URL, hostname,
IP, criticality, and description. Reads are open to authenticated users; create/edit/delete
are Analyst/Admin only. Assets with linked findings **cannot be deleted** (model-level
`PROTECT` returns HTTP 409 with an explanatory message — no cascade, no force delete).
New assets immediately appear in the Findings ZAP target selector.

## Notifications & Audit Trail

- **Notifications** — server-created per workflow event (assignments, remediation readiness,
  verification, closure, scanner syncs). Users see their own; analysts see everyone's with
  the recipient labeled. Only the `is_read` flag on your own rows is writable.
- **Audit Logs** — read-only, Administrator/Security Analyst only: every review, promotion,
  transition, assignment, due-date change, remediation update, AI generation, and scan/sync
  action with actor, entity, old → new values, and timestamp.

## Project Structure

```
CyberShield/
├── backend/
│   ├── config/          # settings, root URLs, health check
│   ├── accounts/        # auth (JWT login/refresh/me), users, roles, permissions
│   ├── security/        # assets, findings, vulnerabilities, remediation,
│   │                    #   notifications, audit, AI + ZAP services, workflows
│   ├── requirements.txt
│   └── manage.py
└── frontend/
    ├── src/
    │   ├── pages/       # Dashboard, Findings, Vulnerabilities, Remediation,
    │   │               #   Assets, AI Assistant, Integrations, Notifications,
    │   │               #   Audit Logs, Users, Settings
    │   ├── components/  # layout (sidebar/header), shared UI
    │   ├── context/     # global app state (SecurityContext)
    │   ├── services/    # Django API client + config
    │   └── data/        # legacy demo-mode fixtures (inactive in real mode)
    └── package.json
```

## Backend Setup

```bash
cd backend
python -m venv ..\venv
..\venv\Scripts\activate        # Windows (use source ../venv/bin/activate on macOS/Linux)
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver      # http://127.0.0.1:8000
```

Then create the `Role` rows (`Administrator`, `Security Analyst`, `IT / Developer`) and a
`UserProfile` linking each user to a role — via the Django admin at `/admin/`. Copy
`.env.example` to `.env` and fill in the values (see Environment Variables).

## Frontend Setup

```bash
cd frontend
npm install
npm run dev     # http://localhost:3000 (real API mode needs VITE_USE_MOCK_DATA=false)
npm run build   # production build into dist/
npm run lint    # TypeScript check (tsc --noEmit)
```

## Environment Variables

Values are never committed — see `frontend/.env.example` and `backend/.env.example`.
Backend (`backend/.env`): `DATABASE_URL`, `SECRET_KEY`, `ZAP_BASE_URL`, `ZAP_API_KEY`,
`GEMINI_API_KEY`. Frontend (`frontend/.env`): `VITE_API_URL` (default
`http://127.0.0.1:8000/api/`), `VITE_USE_MOCK_DATA` (`false` = real Django backend,
anything else = local demo fixtures).

## Important API Endpoints

- `GET /api/health/` · `POST /api/auth/login|refresh/` · `GET /api/auth/me` · `GET /api/users/`
- `GET /api/findings/` (paginated, `?search=&severity=&status=&asset=`) · `GET /api/findings/stats/`
- `POST /api/findings/{id}/review|` · `POST /api/findings/{id}/promote/`
- `GET /api/findings/zap/test-connection/` · `POST /api/findings/zap/scan/` · `GET /api/findings/zap/scan-status/` · `POST /api/findings/zap/sync/`
- `GET|POST /api/assets/` · `GET|PATCH|DELETE /api/assets/{id}/`
- `GET /api/vulnerabilities/` · `POST /api/vulnerabilities/{id}/assign|due-date|verify|transition/`
- `POST /api/vulnerabilities/{id}/ai-analysis/` · `GET /api/vulnerabilities/{id}/ai-analyses/`
- `GET|POST|PATCH /api/remediation/` · `GET /api/notifications/` (+ `read`, `mark-all-read`) · `GET /api/audit-logs/`

## Demo Workflow

1. Log in as analyst → Dashboard KPIs → Findings (test ZAP connection).
2. Scan Website on OWASP Juice Shop → track 100% → Sync Findings → review a NEW finding.
3. Mark Reviewed → Promote with Impact/Likelihood → open the vulnerability.
4. Assign to the developer → log in as developer → Start progress → Mark remediated.
5. Back as analyst → Verify remediation → Close; show synced remediation task, notifications, audit trail.
6. Generate AI guidance on an assigned vulnerability; view history; check Users, Assets, Audit Logs.

## Security Considerations

- JWT access (30 min) + refresh (1 day) rotation; API keys and `SECRET_KEY` live only in
  backend env, never in code, logs, errors, or the frontend (ZAP error text is redacted).
- Every privileged action is authorized server-side (analyst gates, assignee checks,
  PROMOTED-terminal findings, strict single-step lifecycle, protected asset deletion).
- Scanner/AI integrations are backend-mediated: no arbitrary scan URLs, no raw evidence or
  secrets sent to Gemini, no auto-import or auto-generation.

## Current MVP Limitations

- ZAP Spider + passive observations only — no full Active Scan yet; scan/sync initiation is manual.
- AI guidance depends on external Gemini availability and quota (failures surface cleanly, nothing is written).
- The ZAP service must be separately running and reachable by the backend; deployment/container orchestration is not part of this repository.
- No asset ownership model, no CVE enrichment, no multi-scanner support beyond ZAP.
