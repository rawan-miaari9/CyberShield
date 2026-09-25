# CyberShield Frontend

React + Vite + TypeScript single-page application for the CyberShield Vulnerability
Management Platform. It orchestrates security workflows through the Django REST backend —
it never contacts scanner or AI services directly.

## Stack

React 19 · TypeScript · Vite 6 · React Router 7 · Tailwind CSS 4 · Axios · Recharts.

## Installation

```bash
npm install
```

## Environment configuration

Copy `.env.example` to `.env`:

- `VITE_API_URL` — Django API base (default `http://127.0.0.1:8000/api/`).
- `VITE_USE_MOCK_DATA` — `false` for the real backend; anything else runs local demo
  fixtures from `src/data/` (development only).

## Scripts

```bash
npm run dev    # local server on http://localhost:3000
npm run build  # production build into dist/
npm run lint   # TypeScript check (tsc --noEmit)
```

## Real API vs mock mode

Real mode (`VITE_USE_MOCK_DATA=false`) calls Django for everything and surfaces genuine API
errors. Mock mode serves static fixtures for UI development only and must never be used to
demonstrate backend-backed workflows (lifecycle, RBAC, audit, AI, ZAP).

See the root `README.md` for full architecture, backend setup, RBAC, API reference, and the
demo workflow.
