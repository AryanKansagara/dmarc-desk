# DMARC Desk

Take a domain from `p=none` to `p=reject` without losing real mail.

Gmail, Yahoo and (since May 2025) Outlook.com reject or junk bulk mail that is not authenticated. Publishing a DMARC record is easy; finishing the rollout is not, because nobody can tell which failures in the reports are their own mail. DMARC Desk is for the IT admin or founder who has to answer that.

## Features

- **Live DNS grade** over DNS-over-HTTPS (Cloudflare, Google fallback), straight from the browser: MX, SPF with full recursive expansion (10-lookup and void-lookup limits, `+all`/`?all`, duplicates, loops), every DMARC tag including external `rua` authorisation records, DKIM at 36 common selectors plus your own, MTA-STS, TLS-RPT, BIMI and DNSSEC (AD flag).
- **Report import**: drop hundreds of aggregate (RUA) reports as `.xml`, `.xml.gz` or `.zip`. Decompressed in the browser with the native DecompressionStream, validated with line numbers, duplicates skipped.
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
```

Cloud sync needs `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY` in `.env` (see `.env.example`). Without them the app runs fully local.

## Live

https://dmarc-desk.vercel.app
