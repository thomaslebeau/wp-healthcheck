# WP Health Check

Automated health monitoring for WordPress sites. Runs daily via GitHub Actions (free), results displayed on a static dashboard hosted on GitHub Pages.

## Checks performed

- **Uptime** — HTTP status + response time
- **SSL/HTTPS** — Ensures site is served over HTTPS
- **Security headers** — X-Content-Type-Options, X-Frame-Options, HSTS, CSP, Referrer-Policy
- **WP version exposed** — Detects `<meta name="generator">` leak
- **CSS integrity** — Verifies stylesheets are loading
- **wp-login exposed** — Checks if default login page is publicly accessible
- **XML-RPC** — Detects if XML-RPC endpoint is active
- **Response time** — Warns if > 3s, alerts if > 6s

## Setup

1. Create a **private** repo `wp-healthcheck` with these files
2. Edit `sites.json` with your site URLs
3. Enable GitHub Pages: Settings → Pages → Source: **Deploy from a branch** → Branch: `main`, folder: `/ (root)`
4. Run the workflow once manually: Actions tab → "Run workflow"
5. Your dashboard is live at `https://<username>.github.io/wp-healthcheck/`

### Manual run

```bash
node healthcheck.mjs
```

The workflow auto-commits `results.json` after each run. The dashboard reads this file.
