# NAZON — Backup & Restore Plan

This document covers how to protect the NAZON database, secrets, and local
state. Update the "Current Setup" section as soon as you pick a permanent host.

## 1. Current Setup (Update when deploying)

- **Host:** None yet (Render free tier expired, exploring options)
- **Database:** Local SQLite (`nazon.db`) for now; PostgreSQL for production
- **Backup Frequency:** N/A (no live production data)

## 2. Secrets (CRITICAL)

Never commit secrets to git.
- `NAZON_SECRET` (signing key, 32+ chars)
- `NAZON_ADMIN_USER`
- `NAZON_ADMIN_PASS`
- `DATABASE_URL`

**Rule:** Keep an encrypted copy of these in a password manager (Bitwarden, 1Password).
If you lose the host, you must be able to recreate the environment.

## 3. Production Database Backups (PostgreSQL)

When deployed, the database must have automated daily backups with at least
7-day retention. 

### If using Render (Basic plan or higher)
- Render handles this automatically. 
- To restore: Dashboard → Database → Backups → Restore.
- **Do not deploy production on Render's free tier.** It does not have backups.

### If using Fly.io
- Fly.io Postgres has automated snapshots, but you should also take manual dumps.
- Create a scheduled GitHub Action or cron job to run:
  `flyctl postgres connect -a <db-app-name> --command "pg_dump -U postgres -Fc" > backup.dump`
- Store the `.dump` file in an encrypted S3 bucket or similar.

### If using a VPS (DigitalOcean, AWS EC2, etc.)
- You are responsible for backups. Set up a cron job:
  `0 2 * * * pg_dump -U postgres -Fc nazon > /backups/nazon-$(date +\%Y\%m\%d).dump`
- Sync `/backups/` to an off-site location (S3, Backblaze B2).

## 4. Manual Backup (Any Host)

From a machine with `pg_dump` installed and `DATABASE_URL` set:

    pg_dump "$env:DATABASE_URL" -Fc -f "nazon-$(Get-Date -Format yyyyMMdd-HHmmss).dump"

Verify the dump is valid (it should list table names):

    pg_restore --list nazon-YYYYMMDD-HHMMSS.dump

## 5. Restore Procedure

To restore a dump to an empty database:

    pg_restore -d "$env:DATABASE_URL" --clean --if-exists nazon-YYYYMMDD-HHMMSS.dump

## 6. Local SQLite Backup (Development)

`nazon.db` is not backed up by default. If you need to save a local testing state:

    Copy-Item nazon.db "nazon-backup-$(Get-Date -Format yyyyMMdd).db"

## 7. Test Your Backups Quarterly

**A backup you have never restored is not a backup.**
Once every 3 months:
1. Spin up a temporary database (local Docker Postgres or a free tier DB).
2. Restore the latest dump into it.
3. Point a local `uvicorn` at that DB using `DATABASE_URL`.
4. Log in, verify vehicles and audit rows exist.

## 8. Restore History

| Date | Tested By | Result | Notes |
|------|-----------|--------|-------|
| (none yet) | | | |