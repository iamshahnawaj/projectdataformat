# Project Data Formatter: Email OTP + Master Password + Admin Panel

## User login flow
1. User enters their registered email address.
2. Server emails a six-digit OTP to that address.
3. User enters the OTP (10-minute expiry, maximum five attempts).
4. User enters the shared master password `Welcome@2026`.
5. PHP session grants access to the formatter.

Admin can create users by adding their email and username, and can disable/enable accounts.

## Hosting requirement
**This does not run on GitHub Pages.** GitHub Pages only serves static files and does not execute PHP, connect to MySQL, or send server-side email. Deploy this project to PHP/MySQL hosting. You can keep the source in GitHub.

## Files
- `index.php`: email OTP login and admin sign-in
- `config.php`: database, mail sender, master-password hash and OTP secret configuration
- `formatter.php`: original formatter behind a server-side PHP session
- `admin.php`: user management panel
- `logout.php`: logout/session cleanup
- `schema.sql`: database schema

## Setup
1. Create a MySQL database and import `schema.sql`.
2. Upload the PHP files to a PHP hosting provider with HTTPS.
3. Set environment variables in your hosting control panel:
   - `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASS`
   - `MAIL_FROM`: verified sender email address
   - `OTP_SECRET`: long random secret, not the sample value
   - `ADMIN_USERNAME`
   - `ADMIN_PASSWORD_HASH`: SHA-256 hash of your chosen admin password
   - `MASTER_PASSWORD_HASH` (optional; defaults to the hash for `Welcome@2026`)
4. Ensure PHP's `mail()` is enabled and configured by your host. If the host requires authenticated SMTP instead, replace the `mail()` call in `index.php` with a provider-approved SMTP library/service. Do not put SMTP credentials in public source code.
5. Configure admin credentials, then open `index.php` and use **Administrator sign in** to create user accounts.
6. Each user must use an email address that has been added in the admin panel.

## Security notes
- OTP is generated using `random_int`, stored as a keyed hash in the session, expires after 10 minutes, and allows up to five attempts.
- OTP delivery requires working email sending on the host. The app does not silently bypass OTP if mail delivery fails.
- `OTP_SECRET` must be changed from its placeholder to a long random secret before deployment.
- The master password is shared across all users, so anyone with an active registered email and the master password can access the tool. Individual passwords are safer.
- Use HTTPS. Do not commit database credentials, mail credentials, or admin secrets to a public repository.
