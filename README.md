<div align="center">
  <img src="public/favicon.svg" width="64" height="64" alt="">
  <h1>DMARC Reports</h1>
  <p><strong>See who sends email as your domains, in plain English, on your own Cloudflare account.</strong><br>
  Free for personal and small business use. Source available.</p>
  <p><a href="https://paulobrien.dev/dmarc/">Website</a> · <a href="#install">Install</a> · <a href="https://github.com/pobren/dmarc-reports/releases">Releases</a> · <a href="https://github.com/pobren/dmarc-reports/issues">Report a bug</a></p>
</div>

Mail providers such as Google, Microsoft and Yahoo send daily DMARC reports about every message that claims to come from your domains. They arrive as zipped XML files that nobody wants to read. DMARC Reports takes them in by email, explains them and walks you safely from `p=none` to `p=reject`, so spoofed email gets blocked and your own email still arrives.

- **Every sender, named.** Google Workspace, Microsoft 365, Mailchimp and the rest are recognised, so you can see at a glance what's yours and what isn't. Mark each one Mine or Not mine.
- **A safe path to p=reject.** It tells you when it's safe to tighten your DMARC record and gives you the exact record to paste.
- **Setup records for your DNS host.** Step by step instructions for Cloudflare, GoDaddy, 123 Reg, IONOS and many more.
- **TLS reports too.** See whether mail to your domains arrives encrypted.
- **Alerts and a weekly summary** by email when a new sender appears or something stops passing.
- **Share a read-only view** with a colleague or your IT person for 14 days.
- **Download every row** as a CSV file, or upload reports you already have.
- **Your brand.** Your own name, logo, colour and support address on every page and email.

Everything runs in your own Cloudflare account: a Worker, a D1 database and Email Routing. Your reports never leave it.

## What you need

- A Cloudflare account. The free plan is fine for most people.
- A domain on that account with **Email Routing** switched on, for your report address. A spare domain works well. Reports for all your other domains, wherever they're hosted, can come to this one address.

## Install

### 1. The installer (recommended)

You need [Node.js](https://nodejs.org) 20 or later and a Cloudflare API token.

```sh
npx @mrpwob/dmarc-reports setup
```

`npx @mrpwob/dmarc-reports help` lists the token permissions. Make the token at [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens) (Create Token, then Create Custom Token). It's only ever sent to Cloudflare.

The installer asks which domain to use, makes the database, uploads the app at `dmarc.<your domain>`, sends `dmarc-reports@<your domain>` to it with Email Routing and gives you a one-time link to set your password. Only that link can set the password, so nobody else can claim your app first.

If Email Routing isn't switched on for the domain, the installer leaves it alone and tells you what to do. Switching it on changes where the domain's email goes, so that's your call.

### 2. Deploy to Cloudflare

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/pobren/dmarc-reports)

The button copies DMARC Reports to your GitHub account, makes its database in your Cloudflare account and deploys it. It asks for one thing:

- **SETUP_TOKEN:** a long secret code you make up, 16 characters or more. Replace the example code: it won't work, so set-up stays locked until you choose your own.

When it's deployed, open `https://<your app's address>/?setup=<your code>` to set your password. Then send your report address to the app (see below).

### 3. From the code

```sh
git clone https://github.com/pobren/dmarc-reports.git
cd dmarc-reports
npm install
npx wrangler secret put SETUP_TOKEN
npm run deploy
```

## Getting reports in

1. **Route your report address to the app.** In Cloudflare, open your domain, then **Email › Email Routing › Routing rules**. Add a custom address such as `dmarc-reports@example.com` with the action **Send to a Worker** and the Worker **dmarc-reports**. (The installer does this for you when Email Routing is on.)
2. **Add the address in the app.** Open **Settings** and put it under **Where reports and alerts go**.
3. **Add your domains.** For each one, the app gives you the DMARC record to add at your DNS host, with the report address already in it.
4. **Other domains.** When a domain's reports go to an address on a different domain, mail providers check that the report domain agrees to take them. The app shows the one extra TXT record you need for that, on the domain's page.

Reports usually start arriving within a day or two.

## Alerts and the weekly summary

Add an address under **Settings › Where reports and alerts go**. Cloudflare only sends to addresses you've verified, so add it first under **Email › Email Routing › Destination addresses**, then press **Send a test email** in the app.

## Forgotten your password?

Run `npx @mrpwob/dmarc-reports setup` again for a new set-up link, or give the `SETUP_TOKEN` secret a new code under **Workers & Pages › dmarc-reports › Settings › Variables and Secrets** and open `https://<your app>/?setup=<new code>`. Each code works once.

## Updating

```sh
npx @mrpwob/dmarc-reports@latest update
```

Your reports and settings are kept. If you used the Deploy button, pull the latest code into your GitHub copy and Cloudflare deploys it.

## Costs

DMARC Reports itself is free within the licence below. It runs on your own Cloudflare account, so Cloudflare's own limits and prices apply. For most people the free plan covers it.

## Help

Found a bug? Please [open an issue](https://github.com/pobren/dmarc-reports/issues). Security problem? Please email the address on [paulobrien.dev/contact](https://paulobrien.dev/contact/) rather than opening an issue.

## Licence

**In short:** free for you or your organisation to use on your own domains, up to 10 of them. You can read, change and run the code. If you'd like to use it for clients, host it for other people or sell it under your own name, you need a commercial licence: [talk to us](https://paulobrien.dev/contact/).

The full terms are the [Business Source License 1.1](LICENSE). Each version becomes Apache 2.0 four years after its release. This summary isn't the licence: if they differ, the LICENSE file wins.

DMARC Reports uses [postal-mime](https://github.com/postalsys/postal-mime) (MIT). See [NOTICE](NOTICE). DMARC Reports is independent and isn't made, endorsed or supported by Cloudflare.
