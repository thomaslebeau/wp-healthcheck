/**
 * WordPress Sites Health Check Script
 * Checks: HTTP status, SSL, security headers, WP version exposure,
 * CSS integrity, login page exposure, XML-RPC, and response time.
 *
 * Usage: node healthcheck.mjs
 * Config: sites.json
 * Notification: Slack webhook (SLACK_WEBHOOK_URL env var)
 */

import https from "node:https";
import http from "node:http";
import { readFileSync } from "node:fs";
import { URL } from "node:url";

// ─── Configuration ───────────────────────────────────────────────────────────

const SITES = JSON.parse(
  readFileSync(new URL("./sites.json", import.meta.url), "utf-8"),
);
const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL || "";
const TIMEOUT_MS = 15000;

const EXPECTED_SECURITY_HEADERS = [
  "x-content-type-options",
  "x-frame-options",
  "strict-transport-security",
  "content-security-policy",
  "referrer-policy",
];

// ─── HTTP helpers ────────────────────────────────────────────────────────────

function fetch(
  url,
  { method = "GET", followRedirects = 5, timeout = TIMEOUT_MS } = {},
) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const client = parsedUrl.protocol === "https:" ? https : http;

    const req = client.request(
      parsedUrl,
      { method, timeout, headers: { "User-Agent": "WP-HealthCheck/1.0" } },
      (res) => {
        if (
          [301, 302, 307, 308].includes(res.statusCode) &&
          res.headers.location &&
          followRedirects > 0
        ) {
          const next = new URL(res.headers.location, url).href;
          resolve(
            fetch(next, {
              method,
              followRedirects: followRedirects - 1,
              timeout,
            }),
          );
          return;
        }

        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf-8"),
          });
        });
      },
    );

    req.on("timeout", () => {
      req.destroy();
      reject(new Error(`Timeout after ${timeout}ms`));
    });
    req.on("error", reject);
    req.end();
  });
}

// ─── Individual checks ───────────────────────────────────────────────────────

async function checkUptime(url) {
  const start = Date.now();
  try {
    const res = await fetch(url);
    const elapsed = Date.now() - start;
    return {
      name: "Uptime",
      ok: res.status >= 200 && res.status < 400,
      detail: `HTTP ${res.status} — ${elapsed}ms`,
      severity:
        res.status >= 500 ? "critical" : res.status >= 400 ? "warning" : "ok",
      _res: res,
      _elapsed: elapsed,
    };
  } catch (err) {
    return {
      name: "Uptime",
      ok: false,
      detail: err.message,
      severity: "critical",
    };
  }
}

function checkSSL(url) {
  const isHttps = url.startsWith("https://");
  return {
    name: "SSL/HTTPS",
    ok: isHttps,
    detail: isHttps ? "HTTPS active" : "Site not served over HTTPS",
    severity: isHttps ? "ok" : "critical",
  };
}

function checkSecurityHeaders(headers) {
  const missing = EXPECTED_SECURITY_HEADERS.filter((h) => !headers[h]);
  return {
    name: "Security headers",
    ok: missing.length === 0,
    detail:
      missing.length === 0 ? "All present" : `Missing: ${missing.join(", ")}`,
    severity:
      missing.length > 2 ? "warning" : missing.length > 0 ? "info" : "ok",
  };
}

function checkWPVersionExposed(body) {
  const match = body.match(
    /<meta\s+name=["']generator["']\s+content=["']WordPress\s+([\d.]+)["']/i,
  );
  return {
    name: "WP version exposed",
    ok: !match,
    detail: match ? `WordPress ${match[1]} visible in source` : "Not exposed",
    severity: match ? "warning" : "ok",
  };
}

function checkCSSIntegrity(body) {
  const linkTags = body.match(/<link[^>]+stylesheet[^>]*>/gi) || [];
  const styleTags = body.match(/<style[\s>]/gi) || [];
  const cssImports = body.match(/@import\s/gi) || [];
  const totalCSS = linkTags.length + styleTags.length + cssImports.length;
  const hasCSS = totalCSS > 0;
  return {
    name: "CSS integrity",
    ok: hasCSS,
    detail: hasCSS
      ? `${totalCSS} CSS source(s) found (${linkTags.length} link, ${styleTags.length} inline, ${cssImports.length} import)`
      : "No CSS detected — possible broken theme",
    severity: hasCSS ? "ok" : "critical",
  };
}

async function checkLoginExposed(baseUrl) {
  try {
    const res = await fetch(`${baseUrl.replace(/\/$/, "")}/wp-login.php`, {
      method: "GET",
    });
    const exposed = res.status === 200 && res.body.includes("wp-login");
    return {
      name: "wp-login exposed",
      ok: !exposed,
      detail: exposed
        ? "Default login page is publicly accessible"
        : "Login page hidden or protected",
      severity: exposed ? "info" : "ok",
    };
  } catch {
    return {
      name: "wp-login exposed",
      ok: true,
      detail: "Not reachable (good)",
      severity: "ok",
    };
  }
}

async function checkXMLRPC(baseUrl) {
  try {
    const res = await fetch(`${baseUrl.replace(/\/$/, "")}/xmlrpc.php`, {
      method: "GET",
    });
    const enabled =
      res.status === 405 ||
      (res.status === 200 && res.body.includes("XML-RPC"));
    return {
      name: "XML-RPC",
      ok: !enabled,
      detail: enabled
        ? "XML-RPC is active (attack surface)"
        : "XML-RPC disabled or blocked",
      severity: enabled ? "warning" : "ok",
    };
  } catch {
    return {
      name: "XML-RPC",
      ok: true,
      detail: "Not reachable (good)",
      severity: "ok",
    };
  }
}

function checkResponseTime(elapsed) {
  const slow = elapsed > 3000;
  const verySlow = elapsed > 6000;
  return {
    name: "Response time",
    ok: !verySlow,
    detail: `${elapsed}ms`,
    severity: verySlow ? "warning" : slow ? "info" : "ok",
  };
}

// ─── Run all checks for one site ─────────────────────────────────────────────

async function auditSite(url) {
  const results = [];

  const uptime = await checkUptime(url);
  results.push(uptime);
  results.push(checkSSL(url));

  if (uptime.ok && uptime._res) {
    results.push(checkSecurityHeaders(uptime._res.headers));
    results.push(checkWPVersionExposed(uptime._res.body));
    results.push(checkCSSIntegrity(uptime._res.body));
    results.push(checkResponseTime(uptime._elapsed));
  }

  results.push(await checkLoginExposed(url));
  results.push(await checkXMLRPC(url));

  return results;
}

// ─── Formatting ──────────────────────────────────────────────────────────────

const ICONS = { critical: "🔴", warning: "🟡", info: "🔵", ok: "✅" };

function formatReport(allResults) {
  const lines = [];
  const now = new Date().toISOString();
  lines.push(`🩺 *WP Health Check — ${now}*\n`);

  let issueCount = 0;

  for (const { url, checks } of allResults) {
    const issues = checks.filter((c) => !c.ok);
    issueCount += issues.length;
    const siteIcon = issues.some((i) => i.severity === "critical")
      ? ICONS.critical
      : issues.length > 0
        ? ICONS.warning
        : ICONS.ok;

    lines.push(`${siteIcon} *${url}*`);
    for (const check of checks) {
      lines.push(`  ${ICONS[check.severity]} ${check.name}: ${check.detail}`);
    }
    lines.push("");
  }

  lines.push(
    issueCount === 0
      ? "All sites healthy ✨"
      : `⚠️ ${issueCount} issue(s) found`,
  );
  return lines.join("\n");
}

// ─── Slack notification ──────────────────────────────────────────────────────

async function sendSlack(text) {
  if (!SLACK_WEBHOOK_URL) {
    console.log("No SLACK_WEBHOOK_URL set — skipping notification.\n");
    return;
  }

  const payload = JSON.stringify({ text });
  const url = new URL(SLACK_WEBHOOK_URL);

  return new Promise((resolve, reject) => {
    const req = https.request(
      url,
      { method: "POST", headers: { "Content-Type": "application/json" } },
      (res) => {
        res.on("data", () => {});
        res.on("end", resolve);
      },
    );
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

// ─── JSON output for dashboard ───────────────────────────────────────────────

async function writeJSON(allResults) {
  const { writeFileSync } = await import("node:fs");
  const output = {
    timestamp: new Date().toISOString(),
    sites: allResults,
  };
  writeFileSync(
    new URL("./results.json", import.meta.url),
    JSON.stringify(output, null, 2),
  );
  console.log("Results written to results.json");
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  console.log(`Checking ${SITES.length} site(s)...\n`);

  const allResults = [];

  for (const url of SITES) {
    console.log(`→ ${url}`);
    const checks = await auditSite(url);
    allResults.push({
      url,
      checks: checks.map(({ _res, _elapsed, ...rest }) => rest),
    });
  }

  const report = formatReport(allResults);
  console.log("\n" + report);

  await writeJSON(allResults);
  if (SLACK_WEBHOOK_URL) await sendSlack(report);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
