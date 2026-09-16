# Tanzania Dating — MVP

A simple full-stack dating web app with:
- User registration/login
- Profiles
- Discover/Like
- Mutual matches
- Chat after matching
- Report users
- Admin login + dashboard
- User deletion and report moderation

## Run locally
1. Install Node.js 18+
2. Run `npm install`
3. Run `npm start`
4. Open `http://localhost:3000`

## Admin
Default admin credentials:
- Email: `admin@tanzaniadating.com`
- Password: `Admin@12345`

For production, set `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and `SESSION_SECRET` environment variables.

## Render
Build Command: `npm install`
Start Command: `npm start`

SQLite is used for this MVP. For production on Render, use a persistent disk or migrate the database to PostgreSQL.
