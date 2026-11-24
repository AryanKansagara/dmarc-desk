# DMARC Desk

Take a domain from `p=none` to `p=reject` without losing real mail.

Gmail, Yahoo and (since May 2025) Outlook.com reject or junk bulk mail that is not authenticated. Publishing a DMARC record is easy; finishing the rollout is not, because nobody can tell which failures in the reports are their own mail. DMARC Desk is for the IT admin or founder who has to answer that.

## Features

- **Live DNS grade** over DNS-over-HTTPS (Cloudflare, Google fallback), straight from the browser: MX, SPF with full recursive expansion (10-lookup and void-lookup limits, `+all`/`?all`, duplicates, loops), every DMARC tag including external `rua` authorisation records, DKIM at 36 common selectors plus your own, MTA-STS, TLS-RPT, BIMI and DNSSEC (AD flag).
- **Report import**: drop hundreds of aggregate (RUA) reports as `.xml`, `.xml.gz` or `.zip`, or the report emails themselves (`.eml`, Google Takeout `.mbox`). Decompressed in the browser with the native DecompressionStream, validated with line numbers, duplicates skipped. Tested against real reports from Google, Microsoft, Mimecast, Fastmail and others (the parsedmarc sample set), including their known quirks.
- **Sender inventory**: every source IP mapped to a service (Google Workspace, Microsoft 365, SendGrid, Mailchimp/Mandrill, Amazon SES, Postmark, HubSpot, Salesforce, Zendesk, Mailgun, Brevo and more) from DKIM/Return-Path domains, netblocks and reverse DNS. Per-sender SPF/DKIM alignment, why it fails, forwarding detection, volume share and the exact setting to change.
- **Readiness score** on legitimate mail only, and a "looks fixed since" signal for senders whose old reports still show failures.
- **SPF builder** that flattens the heaviest includes to stay under 10 lookups.
- **Staged rollout planner**: none, quarantine 10/50/100%, reject 50/100%, with dates and gates.
- **Generated records**: SPF, DMARC, MTA-STS (policy file and a Cloudflare Worker to serve it), TLS-RPT, plus a BIND snippet for Cloudflare's zone import.
- **Weekly snapshots** with a compare view, a printable leadership report, CSV export.
- Local-first workspace (IndexedDB), optional email/password sync via Supabase, export and delete controls, light and dark themes.
- Two synthetic sample domains (`example.com`, `example.org`) to explore without your own data.

## Run locally

```sh
npm install
npm run dev      # http://localhost:5173
npm test         # engine tests (node --test)
npm run build
npm run test:e2e # browser tests (Playwright), see below
```

### End-to-end tests

`npm run test:e2e` builds the app and runs the Playwright (Chromium) suite in `e2e/` against that production build, served by `vite preview` on port 4390 (set `E2E_PORT` to change it). The first time, install the browser with `npx playwright install chromium` (add `--with-deps` on a bare Linux box).

The tests never touch the network. DNS-over-HTTPS, the MTA-STS proxy route and Google Fonts are stubbed per test; any other request that is not the preview server is blocked and fails the test, and so does an uncaught page error. Every test starts signed out in an empty browser profile, so no Supabase request is made. Report files come from `src/engine/fixtures`.

A few tests are marked `test.fail()`: each reproduces a known app bug that has its own GitHub issue (linked in the test). They are expected to fail until the bug is fixed; then Playwright flags them as unexpectedly passing and the marker goes.

GitHub Actions runs the build, the unit tests and these tests on every pull request and push to `main` (job `test`). Vercel deploys only `main`: `vercel.json` turns off preview deployments for other branches.

Cloud sync needs `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY` in `.env` (see `.env.example`). Without them the app runs fully local.

## Live

https://dmarc-desk.vercel.app
