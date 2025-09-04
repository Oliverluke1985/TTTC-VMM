# StageCrew Tracker (Live Theater & Music Venue Volunteer Hours)

A lightweight time tracking app inspired by Track It Forward, tailored for theaters and music venues. Supports superadmins (multi-organization), admins (per org), and volunteers.

## Features
- JWT-based auth with roles: volunteer, admin, superadmin
- Orgs (groups), events, duties
- Volunteer clock in/out with hour calculations and admin approvals
- Milestones for volunteers
- Admin CSV export of timesheets
- Simple single-file HTML frontend served by Express
- Optional branding and theme colors via env
- Photo uploads for volunteer work evidence with admin approvals

## Requirements
- Node.js 18+
- PostgreSQL 13+

## Environment
Create a `.env` file at the repo root with:

```
DATABASE_URL=postgres://USER:PASSWORD@HOST:5432/DBNAME
PGSSLMODE=disable
JWT_SECRET=replace-with-a-long-random-string
PORT=3000
# Optional branding/theme
APP_NAME=StageCrew Tracker
LOGO_URL=https://example.com/path/to/logo.png
THEME_PRIMARY=#0b6
THEME_ACCENT=#0a84ff
BG_IMAGE_URL=https://example.com/bg.jpg
```

If deploying to a platform that enforces SSL (e.g., Render/Heroku), set `PGSSLMODE=require`.

## Install & Run

1) Install dependencies

```
npm install
```

2) Initialize database schema and seeds

```
# Ensure DATABASE_URL is set in your environment or .env
npm run init:db
```

3) Start the server

```
npm run dev   # hot-reload in development
# or
npm start     # production
```

Open `http://localhost:3000` and log in using one of the seeded superadmin accounts from `bootstrap.sql` (password: `password123`).

## Signup (Public Registration)
- New volunteers can self-register on the home screen.
- The app fetches active organizations from `GET /public/groups` for selection during signup (optional).
- Submitting the form calls `POST /signup` with `{ name, email, password, phone?, address?, group_id? }` and auto-logs the user in on success.

API endpoints:
- `GET /public/groups` → `[{ id, name }]` active orgs
- `POST /signup` → body `{ name, email, password, phone?, address?, group_id? }` → `{ token, role:'volunteer', group_id, id }`

## Seeded Superadmins
- oliver@ticketstothecity.com / password123
- trusted@ticketstothecity.com / password123
- admin@example.com / password123

## Notes
- Superadmins can create organizations (groups).
- Admins can create events and duties for their organization and approve volunteer time.
- Volunteers can clock in/out and see their milestones.
- The app exposes `/config` for branding (title & logo) and theme colors.

## CSV Export
Admins and superadmins can download CSV timesheets from the Admin section or via `GET /time-tracking.csv`.

## Photos (Work Evidence)
- Volunteers can upload photos per duty using the camera or file picker.
- Admins/superadmins can view and approve photos (scoped to org; superadmins see all).
- Files are stored in `uploads/` and served at `/uploads/...`.

## Deployment
- Provide `DATABASE_URL`, `JWT_SECRET`, and branding/theme env vars to your host.
- Ensure `PGSSLMODE=require` if your provider requires SSL for PostgreSQL.
- Set a strong `JWT_SECRET`.
- Behind a proxy/load balancer, ensure it forwards `X-Forwarded-*` headers if you terminate TLS upstream.

## API Quick Reference
- POST `/login` { email, password } → `{ token, role, group_id, id }`
- GET `/me` (auth) → profile
- POST `/account` (auth) → update name/email/phone/address
- GET `/config` → `{ appName, logoUrl, primaryColor, accentColor, bgImageUrl }`
- GET `/groups` (auth), POST `/groups` (superadmin), DELETE `/groups/:id`
- GET `/events` (auth, scoped), POST `/events` (admin)
- GET `/duties` (auth, scoped), POST `/duties` (admin)
- POST `/duties/:id/time/start` (auth), POST `/duties/:id/time/end` (auth)
- GET `/time-tracking` (auth, scoped), GET `/time-tracking.csv` (auth, scoped)
- PATCH `/time-tracking/:id` (admin/superadmin), DELETE `/time-tracking/:id` (admin/superadmin)
- GET `/approvals` (admin, scoped), POST `/approvals/:id/approve` (admin)
- POST `/time-tracking/:id/approve` (admin alias)
- GET `/milestones` (volunteer own), GET `/milestones/:id` (admin/own), POST `/milestones`
- POST `/duties/:id/photos` (auth) multipart form `photo` and optional `caption`
- GET `/photos` (auth, scoped), POST `/photos/:id/approve` (admin)
