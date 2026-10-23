# TrustVault — Secure Document Sharing

A Flask + SQLite starter implementation inspired by the supplied TrustVault reference. Includes registration, login, owner/admin/viewer roles, private document storage, sharing grants, document search, and admin-only audit logs.

## Requirements
- Python 3.10+
- Windows, macOS, or Linux

## Run on Windows (PowerShell)
```powershell
cd path\to\trustvault_web
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python run.py
```
Open http://127.0.0.1:5000

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal, then activate again.

## First admin account
Public signup always creates an `owner` account. To promote a user to admin for a local demo, first register that account, stop the server, then run:
```powershell
python make_admin.py your-email@example.com
```
Restart the server. Do not expose the demo database or this development setup to the public internet.

## Security notes
- Passwords are hashed using Werkzeug.
- Files are stored outside the static web directory and served only after authorization.
- Public signup cannot choose an admin role.
- Sharing and revocation are restricted to the owner or admin.
- Audit logs are admin-only.
- File size limit is 16 MB and file extensions are allowlisted.
- This is a hackathon starter, not a production security certification. Before public deployment, add CSRF protection, rate limiting, email verification/password reset, malware scanning, stronger content validation, secure secret configuration, and deployment hardening.
