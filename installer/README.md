# DMARC Reports installer

Installs and updates [DMARC Reports](https://github.com/pobren/dmarc-reports) on your own Cloudflare account. DMARC Reports reads your domains' DMARC and TLS reports and tells you, in plain English, who is sending email as your domains and when it's safe to tighten your DMARC record. Your reports stay on your account.

```sh
npx @mrpwob/dmarc-reports setup            # install
npx @mrpwob/dmarc-reports@latest update    # update to the newest version
npx @mrpwob/dmarc-reports help             # every option, and the token permissions
```

You need [Node.js](https://nodejs.org) 20 or later and a Cloudflare API token. Make the token at [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens) (Create Token, then Create Custom Token) with the permissions `help` lists. Set it as `CLOUDFLARE_API_TOKEN`, or paste it when asked. It's only ever sent to Cloudflare.

The installer makes the database (D1), uploads the app, gives it its web address, sends your report address to it with Email Routing and hands you a one-time link to set your password. Running it again is safe: your reports are kept.

Found a bug? Please [open an issue](https://github.com/pobren/dmarc-reports/issues).

Free for personal and small business use, source available, under the Business Source License 1.1. See LICENSE. DMARC Reports is independent and isn't made, endorsed or supported by Cloudflare.
