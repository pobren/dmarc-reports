# Changes

## 1.2.0: API, webhooks and AI connector

- A public API at /api/v1 with your own keys, read only or able to change things. Guide at paulobrien.dev/dmarc/api.
- Signed webhooks when a report arrives and when an alert is due.
- An AI connector at /mcp, so you can ask Claude about your reports. It can only read.
- All three are in Settings, under API, webhooks and AI connector.

## 1.1.0: Optional robot check

- Set-up and sign-in can now use Cloudflare Turnstile. It's off until you add your own widget's keys to the Worker (see Robot check in the README).

## 1.0.1: Releases straight from GitHub

- New versions now go to npm straight from GitHub, with a signature you can check on npm. Nothing changes in the app.

## 1.0.0: First release

- DMARC and TLS reports by email, explained in plain English.
- Every sender named, with Mine and Not mine.
- A step by step path from p=none to p=reject.
- Setup records for many DNS hosts.
- Alerts, a weekly summary, read-only share links, CSV downloads and report uploads.
- Your own name, logo, colour and support address.
- The installer: npx @mrpwob/dmarc-reports.
