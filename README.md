# Codebase Technologies — Code Quality Portal

Existing report studio, running on standard Next.js / Node.js with MongoDB-backed accounts. The purple report design and logo paths are retained.

## Apply this update

Back up your existing project first. This archive contains replacement source files, not a new project to register or deploy. Replace the old `app` folder rather than merging it: `app/page.tsx` is now the server-side access check, and your report UI lives in `app/report-studio.tsx`. Replace the supplied root files and use the supplied `lib`, `scripts`, and `tests` folders. Remove the obsolete runtime folders and files listed in the handoff before installation.

Keep your current `public` folder, including `codebase-technologies-logo.png` and `favicon.svg`. Keep your existing `.env.local` and Sonar credentials; this archive does not contain or overwrite them. Do not carry over old `node_modules` or build output; `npm ci` recreates dependencies from the updated lockfile.

Node.js 22.13 or newer is required. Commands below work in Windows PowerShell from the existing project directory.

## 1. Prepare MongoDB Atlas

Create a Free cluster in your Atlas account. Create a database user with `readWrite` permission on a dedicated database named `code_cop`, not administrator access to all databases. This database user is separate from the portal users.

In Atlas Network Access, add only your current public IP. Avoid opening access to every IP. If your ISP changes your IP, update the allowlist. Use Connect → Drivers → Node.js to obtain the connection string. URL-encode special characters in its password. A cloud database requires working internet access even though the web app is local.

Use test accounts until your company approves storing employee account information with this provider. The portal stores account names, email addresses, password hashes, session hashes, and login-attempt counters; it does not save Sonar reports in MongoDB.

## 2. Configure the application

Add the following entries to your existing `.env.local` using `.env.example` as a reference:

```env
MONGODB_URI=mongodb+srv://DATABASE_USER:URL_ENCODED_PASSWORD@CLUSTER_HOST/?retryWrites=true&w=majority
MONGODB_DB=code_cop
APP_ORIGIN=http://localhost:5173
```

Keep `SONAR_BASE_URL`, `SONAR_TOKEN`, and `SONAR_ORGANIZATION` as already configured. Never paste credentials into screenshots, source files, or a public repository. Do not add a `NEXT_PUBLIC_` prefix to credentials.

## 3. Install and create your administrator

```powershell
npm.cmd ci
npm.cmd run admin:create
```

The command asks for name, email, and a password of 15–128 characters. Password entry is hidden, including while pasting. It creates the MongoDB collections and indexes as needed. There are no default credentials and no public signup or setup endpoint.

Run the administrator command only from a trusted local terminal. It refuses duplicate emails. It can also create a separately named administrator account for recovery if the original administrator forgets their password; it never overwrites an existing account.

## 4. Start and sign in

```powershell
npm.cmd run dev
```

Open **http://localhost:5173**. Use that exact origin, matching `APP_ORIGIN`. The server binds to loopback, so it is not exposed to the LAN. Restart after changing `.env.local`.

Sign in, select **Manage users**, and create administrator or viewer accounts. Viewers can generate reports but cannot manage accounts. Administrators can disable/enable viewer accounts and set their passwords. Administrator accounts cannot be disabled through the UI, and one administrator cannot reset another administrator's password through the UI. You can change your own administrator password; this signs you out.

All active portal users share the project visibility granted to the configured Sonar service token. There is no per-project allowlist in this update. Use a least-privilege, read-only Sonar account. Existing report category filters and the 100-issue/100-hotspot result limits remain; this is not a new reporting engine or an exhaustive security-framework audit.

## Authentication behavior

- Passwords: salted scrypt hashes; passwords are never returned by APIs.
- Sessions: 256-bit random tokens; only SHA-256 hashes stored in MongoDB.
- Cookies: HttpOnly, SameSite=Lax; Secure when `APP_ORIGIN` uses HTTPS.
- Expiry: eight hours, enforced by every authenticated request independently of MongoDB TTL cleanup.
- Revocation: logout invalidates that session; password reset or status changes invalidate all prior sessions.
- Authorization: report page, administrator page, Sonar API, and account APIs all check authentication server-side.
- CSRF checks: state-changing requests must match the configured origin.
- Throttling: at most 10 login attempts per email and 100 across the app per 15-minute fixed window, including successful attempts. Counters persist in MongoDB. These conservative limits are intended for a small internal MVP.
- Failure handling: a missing database or Sonar connection produces an error, never an authenticated bypass or a fake report.

## Build and verification

```powershell
npm.cmd run typecheck
npm.cmd test
npm.cmd run build
npm.cmd run test:http
```

`test:http` starts and stops a temporary production web server on port 5188 with no database credentials. It verifies redirects, anonymous API rejection, origin enforcement, and configuration errors. It requires the production build first.

Optional database integration test:

```powershell
npm.cmd run test:integration
```

This test downloads a MongoDB test binary on first use and starts a disposable, loopback-only database. It never uses your Atlas database. It tests duplicate emails, password verification, session persistence/expiry/revocation, disabled accounts, password resets, and throttling. Database integration tests could not run in the build environment because the temporary database process was blocked by operating-system permissions. They must still be run in your local environment; successful Atlas connectivity is not yet verified.

After connecting Atlas, verify manually: create admin → sign in → create viewer → sign in as viewer → confirm user management is denied → disable viewer as admin → confirm viewer is denied → reset password → confirm old password no longer works → sign out → confirm report/API access is blocked.

## Later AWS deployment

No deployment is performed by this update. Before exposing the portal beyond your machine, use HTTPS, set `APP_ORIGIN` to the real origin, configure deployment networking and secrets, review backup and recovery needs, and add appropriate operational monitoring and edge rate limiting. Do not simply expose the development server publicly. Atlas can remain the database while application hosting moves separately.
