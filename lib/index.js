/**
 * dsh-password-login — password login + an in-app settings section for the DSH web UI.
 *
 * DSH 0.2.2 authenticates browsers with a per-process launch token ("?token=...")
 * exchanged once for an authority-bound signed cookie. This plugin adds a
 * password door in front of that: it serves <path>, verifies a password against a
 * scrypt hash, and mints the very same cookie the built-in BrowserAuth mints —
 * so the trust fence, the /api admission path and the cookie lifetime stay
 * untouched. The pages use the DSH light theme palette (#f9fafb canvas, #fff
 * cards, #0f1115 text, #5686fe accent) so the door looks like the product.
 *
 * Routes (all under the configured login path):
 *   GET  <path>            login page (redirects to next/"/" when the cookie is valid)
 *   POST <path>            password exchange
 *   GET  <path>/logout     clear the cookie
 *   GET/POST <path>/api/*  JSON half, consumed only by the DSH settings dialog
 *
 * There is no standalone settings page. The one and only settings UI is the
 * "登录安全" section this plugin registers inside DSH's own settings dialog
 * (client.js); it talks to the /api routes above with the session cookie.
 *
 * Cookie shape (private to @deepseek-ai/dsh-client-connection, replicated here
 * on purpose — re-check after a DSH upgrade):
 *   name    "dsh-auth-" + base64url(sha256(authority))
 *   value   "v1." + base64url(JSON{version:1,authority,issuedAt,expiresAt}) + "." + base64url(HMAC-SHA256(body))
 *   secret  the "client-connection/browser-session" grant record in ctx.credentials
 *   cookie  Max-Age / Path=/ / Expires / HttpOnly / SameSite=Strict (/ Secure on TLS)
 */
import { createHash, createHmac, randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { chmod, mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);

export const name = "dsh-password-login";
export const inject = ["webServer", "credentials", "connection"];

const COOKIE_PREFIX = "dsh-auth-";
const COOKIE_VERSION = 1;
const SECRET_BYTES = 32;
const SECRET_RECORD = "client-connection/browser-session";
const DAY_MS = 86400000;
const MAX_BODY_BYTES = 16384;
const SCRYPT_MAXMEM = 128 * 1024 * 1024;
const SCRYPT_N = 32768;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 32;

const DEFAULTS = {
  passwordFile: join(homedir(), ".dsh", "password-login.json"),
  settingsFile: join(homedir(), ".dsh", "password-login.settings.json"),
  path: "/__dsh_login",
  indexPath: "/index.html",
  maxAgeDays: 30,
};

const DEFAULT_SETTINGS = {
  version: 1,
  crossOrigin: "strict",
  allowedOrigins: [],
  maxAttempts: 10,
  lockMinutes: 10,
  cookieMaxAgeDays: 30,
};

const CROSS_ORIGIN_MODES = ["strict", "allowlist", "off"];

function base64url(buffer) {
  return Buffer.from(buffer).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

function parseBase64url(text) {
  if (typeof text !== "string" || text.length === 0 || !/^[A-Za-z0-9_-]+$/u.test(text)) return undefined;
  const padded = text.replace(/-/g, "+").replace(/_/g, "/");
  const decoded = Buffer.from(padded + "=".repeat((4 - (padded.length % 4)) % 4), "base64");
  return base64url(decoded) === text ? decoded : undefined;
}

function normalizePath(value) {
  const text = typeof value === "string" && value.length > 0 ? value : DEFAULTS.path;
  const absolute = text.startsWith("/") ? text : "/" + text;
  return absolute !== "/" && absolute.endsWith("/") ? absolute.slice(0, -1) : absolute;
}

function safeNext(value) {
  if (typeof value !== "string" || value.length === 0 || !value.startsWith("/") || value.startsWith("//")) return "/";
  return value;
}

function cookieName(authority) {
  return COOKIE_PREFIX + base64url(createHash("sha256").update(authority).digest());
}

function signature(secret, body) {
  return createHmac("sha256", secret).update(body).digest();
}

function encodeCookie(payload, secret) {
  const body = base64url(Buffer.from(JSON.stringify(payload), "utf8"));
  return "v" + payload.version + "." + body + "." + base64url(signature(secret, body));
}

function decodeCookie(value, secret) {
  const parts = value.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") return undefined;
  const actual = parseBase64url(parts[2]);
  if (actual === undefined) return undefined;
  const expected = signature(secret, parts[1]);
  if (actual.byteLength !== expected.byteLength || !timingSafeEqual(actual, expected)) return undefined;
  const body = parseBase64url(parts[1]);
  if (body === undefined) return undefined;
  let payload;
  try {
    payload = JSON.parse(body.toString("utf8"));
  } catch {
    return undefined;
  }
  if (payload === null || typeof payload !== "object" || payload.version !== COOKIE_VERSION) return undefined;
  if (typeof payload.authority !== "string" || !Number.isSafeInteger(payload.issuedAt) || !Number.isSafeInteger(payload.expiresAt)) return undefined;
  const now = Date.now();
  if (payload.issuedAt > now || payload.expiresAt <= now || payload.expiresAt <= payload.issuedAt) return undefined;
  return payload;
}

/** Same normalization as the host's requestAudience: HTTP keeps host:port, HTTPS keeps the origin. */
function audienceOf(host, secure) {
  if (typeof host !== "string" || host.length === 0) return undefined;
  try {
    const url = new URL((secure ? "https:" : "http:") + "//" + host);
    return secure ? url.origin : url.host;
  } catch {
    return undefined;
  }
}

function originHost(origin) {
  try {
    return new URL(origin).host;
  } catch {
    return undefined;
  }
}

function cookieFrom(headerValue, target) {
  if (typeof headerValue !== "string") return undefined;
  for (const segment of headerValue.split(";")) {
    const at = segment.indexOf("=");
    if (at === -1) continue;
    if (segment.slice(0, at).trim() === target) return segment.slice(at + 1).trim();
  }
  return undefined;
}

function sessionCookie(name, value, expiresAt, maxAgeSeconds, secure) {
  const attributes = name + "=" + value + "; Max-Age=" + String(maxAgeSeconds) + "; Path=/; Expires=" + new Date(expiresAt).toUTCString() + "; HttpOnly; SameSite=Strict";
  return secure ? attributes + "; Secure" : attributes;
}

function escapeHtml(text) {
  return String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/* Palette lifted from @deepseek-ai/dsh-client-ui-theme (light): canvas #f9fafb,
   layer #fff, label primary #0f1115, secondary #61666b, tertiary #979da6,
   border #e1e5ee, deepseek accent #5686fe. */
const STYLE = ":root{color-scheme:light}" +
  "*{box-sizing:border-box}" +
  "body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font:15px/1.55 system-ui,-apple-system,'Segoe UI',sans-serif;background:#f9fafb;color:#0f1115;padding:24px}" +
  ".card{width:100%;max-width:400px;background:#fff;border:1px solid #e1e5ee;border-radius:16px;padding:28px;box-shadow:0 1px 2px rgba(15,17,21,.04),0 12px 32px rgba(15,17,21,.05)}" +
  ".card.wide{max-width:780px}" +
  ".brand{display:flex;align-items:center;gap:10px;margin-bottom:18px}" +
  ".mark{width:30px;height:30px;flex:none;display:block}" +
  "h1{margin:0;font-size:17px;font-weight:600;letter-spacing:.01em}" +
  "h2{margin:26px 0 4px;font-size:13px;color:#61666b;font-weight:600;text-transform:uppercase;letter-spacing:.06em}" +
  "p.hint{margin:0 0 18px;color:#61666b;font-size:13px}" +
  "p.section{margin:0 0 12px;color:#979da6;font-size:12.5px}" +
  "label{display:block;margin:14px 0 6px;font-size:13px;color:#61666b}" +
  "input[type=password],input[type=text],input[type=number],textarea,select{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #e1e5ee;background:#fff;color:#0f1115;font:inherit}" +
  "input:focus,textarea:focus,select:focus{outline:none;border-color:#5686fe;box-shadow:0 0 0 3px rgba(86,134,254,.16)}" +
  "textarea{min-height:76px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px}" +
  "button{margin-top:18px;padding:10px 18px;border:0;border-radius:10px;background:#5686fe;color:#fff;font:inherit;font-weight:600;cursor:pointer}" +
  "button:hover{background:#4176e6}" +
  "button.wide{width:100%}" +
  ".row{display:flex;gap:14px}.row>*{flex:1}" +
  ".err{margin:0 0 14px;padding:10px 12px;border-radius:10px;background:#fef2f2;color:#b42318;border:1px solid #fecaca;font-size:13px}" +
  ".ok{margin:0 0 14px;padding:10px 12px;border-radius:10px;background:#ecfdf3;color:#067647;border:1px solid #abefc6;font-size:13px}" +
  ".note{margin:0 0 14px;padding:10px 12px;border-radius:10px;background:#f5f7fa;color:#61666b;border:1px solid #e9ecf2;font-size:12.5px}" +
  "table{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:8px}" +
  "th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #edf0f4;color:#43454a;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}" +
  "th{color:#979da6;font-weight:600}" +
  ".pass{color:#067647}.fail{color:#b42318}" +
  "a{color:#4176e6;text-decoration:none}a:hover{text-decoration:underline}" +
  "code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:#43454a;background:#f5f7fa;padding:1px 5px;border-radius:5px}" +
  ".muted{color:#979da6;font-size:12.5px}" +
  ".foot{margin-top:20px;padding-top:16px;border-top:1px solid #edf0f4;color:#979da6;font-size:12.5px;line-height:1.9}";

/**
 * The official DeepSeek whale, taken verbatim from the host's own mark
 * (dsh-web-frontend/dist/favicon.svg == the FishLogo primitive the sidebar
 * draws) and recoloured to the DeepSeek brand blue. Inlined because the login
 * page is served with `default-src 'none'` and may not fetch anything.
 */
const WHALE_PATH = "M48.8354 10.0479C48.3232 9.79199 48.1025 10.2798 47.8032 10.5278C47.7007 10.6079 47.6143 10.7119 47.5273 10.8076C46.7793 11.624 45.9048 12.1597 44.7622 12.0957C43.0923 12 41.666 12.5356 40.4058 13.8398C40.1377 12.2319 39.2476 11.272 37.8926 10.6558C37.1836 10.3359 36.4668 10.0156 35.9702 9.31982C35.6235 8.82373 35.5293 8.27197 35.356 7.72754C35.2456 7.3999 35.1353 7.06396 34.7651 7.00781C34.3633 6.94385 34.2056 7.2876 34.0479 7.57568C33.418 8.75195 33.1733 10.0479 33.1973 11.3599C33.2524 14.312 34.4736 16.6641 36.8999 18.3359C37.1758 18.5278 37.2466 18.7197 37.1597 19C36.9946 19.5757 36.7974 20.1357 36.624 20.7119C36.5137 21.0801 36.3486 21.1597 35.9624 21C34.6309 20.4321 33.481 19.5918 32.4644 18.5757C30.7393 16.8721 29.1792 14.9917 27.2334 13.52C26.7764 13.1758 26.3193 12.856 25.8467 12.5518C23.8618 10.584 26.1069 8.96777 26.627 8.77588C27.1704 8.57568 26.8159 7.8877 25.0591 7.896C23.3022 7.90381 21.6953 8.50391 19.647 9.30371C19.3477 9.42383 19.0322 9.51172 18.7095 9.58398C16.8501 9.22363 14.9199 9.14355 12.9033 9.37598C9.10596 9.80762 6.07275 11.6396 3.84326 14.7681C1.16455 18.5278 0.53418 22.7998 1.30664 27.2559C2.11768 31.9521 4.46582 35.8398 8.07373 38.8799C11.8159 42.0322 16.1255 43.5762 21.041 43.2803C24.0269 43.104 27.3516 42.6963 31.1016 39.4561C32.0469 39.936 33.0396 40.1279 34.686 40.272C35.9546 40.3921 37.1758 40.208 38.1211 40.0078C39.6021 39.688 39.4995 38.2881 38.9639 38.0322C34.623 35.9678 35.5762 36.8081 34.71 36.1279C36.9155 33.4639 40.2402 30.6958 41.54 21.728C41.6426 21.0161 41.5557 20.5679 41.54 19.9917C41.5322 19.6396 41.6108 19.5039 42.0049 19.4639C43.0923 19.3359 44.1479 19.0317 45.1167 18.4878C47.9292 16.9199 49.064 14.3438 49.3315 11.2559C49.3711 10.7837 49.3237 10.2959 48.8354 10.0479ZM24.3262 37.8398C20.1196 34.4639 18.0791 33.3521 17.2358 33.3999C16.4482 33.4482 16.5898 34.3682 16.7632 34.9678C16.9443 35.5601 17.1812 35.9683 17.5117 36.4878C17.7402 36.832 17.8979 37.3442 17.2832 37.728C15.9282 38.584 13.5728 37.4399 13.4624 37.3838C10.7207 35.7358 8.42822 33.5601 6.81348 30.584C5.25342 27.7197 4.34766 24.6479 4.19775 21.3677C4.1582 20.5757 4.38672 20.2959 5.15869 20.1519C6.17529 19.96 7.22314 19.9199 8.23926 20.0718C12.5327 20.7119 16.1885 22.6719 19.2529 25.7759C21.002 27.5439 22.3252 29.6558 23.6885 31.7202C25.1377 33.9121 26.6978 36 28.6831 37.7119C29.3843 38.312 29.9434 38.7681 30.479 39.104C28.8643 39.2881 26.1699 39.3281 24.3262 37.8398ZM26.3433 24.6001C26.3433 24.248 26.6191 23.9678 26.9658 23.9678C27.0444 23.9678 27.1152 23.9839 27.1782 24.0078C27.2651 24.04 27.3438 24.0879 27.4067 24.1602C27.5171 24.272 27.5801 24.4321 27.5801 24.6001C27.5801 24.9521 27.3042 25.2319 26.9575 25.2319C26.6108 25.2319 26.3433 24.9521 26.3433 24.6001ZM32.6064 27.8799C32.2046 28.0479 31.8027 28.1919 31.4165 28.208C30.8179 28.2397 30.1641 27.9922 29.8096 27.688C29.2583 27.2158 28.8643 26.9521 28.6987 26.1279C28.6279 25.7759 28.6675 25.2319 28.7305 24.9199C28.8721 24.248 28.7144 23.8159 28.2495 23.4238C27.8716 23.104 27.3911 23.0161 26.8633 23.0161C26.666 23.0161 26.4849 22.9277 26.3511 22.856C26.1304 22.7441 25.9492 22.4639 26.1226 22.1201C26.1777 22.0078 26.4458 21.7358 26.5088 21.688C27.2256 21.272 28.0527 21.4077 28.8169 21.7197C29.5259 22.0161 30.0615 22.5601 30.834 23.3281C31.6216 24.2559 31.7632 24.5117 32.2124 25.208C32.5669 25.752 32.8901 26.312 33.1104 26.9521C33.2446 27.3521 33.0713 27.6802 32.6064 27.8799Z";
const BRAND_MARK = '<svg class="mark" viewBox="0 0 50 50" role="img" aria-label="DeepSeek"><path d="' + WHALE_PATH + '" fill="#4d6bfe" fill-rule="nonzero"/></svg>';

function layout(title, body, wide) {
  return "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">" +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    "<title>" + escapeHtml(title) + "</title><style>" + STYLE + "</style></head><body>" +
    '<div class="card' + (wide ? " wide" : "") + '">' + body + "</div></body></html>";
}

function send(res, status, body, headers) {
  const base = {
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "content-type": "text/html; charset=utf-8",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  };
  res.writeHead(status, { ...base, ...(headers || {}) });
  res.end(body);
}

function redirect(res, location, extraHeaders) {
  res.writeHead(303, {
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    location: location,
    ...(extraHeaders || {}),
  });
  res.end();
}

function renderLogin(loginPath, message, next) {
  const notice = message === undefined ? "" : '<div class="err">' + escapeHtml(message) + "</div>";
  const hidden = next === "/" ? "" : '<input type="hidden" name="next" value="' + escapeHtml(next) + '">';
  return layout("DeepSeek Harness · 登录",
    '<div class="brand">' + BRAND_MARK + "<h1>DeepSeek Harness</h1></div>" +
    '<p class="hint">输入访问密码以继续</p>' + notice +
    '<form method="post" action="' + escapeHtml(loginPath) + '">' + hidden +
    '<input type="password" name="password" autocomplete="current-password" autofocus required placeholder="访问密码">' +
    '<button class="wide" type="submit">登录</button></form>');
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.byteLength;
    if (size > MAX_BODY_BYTES) return undefined;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function readPasswordRecord(file) {
  return readFile(file, "utf8").then((text) => {
    const record = JSON.parse(text);
    if (record === null || typeof record !== "object" || record.version !== 1) throw new Error("unsupported password record");
    const salt = parseBase64url(record.salt);
    const hash = parseBase64url(record.hash);
    if (salt === undefined || hash === undefined || hash.byteLength < 16) throw new Error("invalid password record");
    const N = Number.isInteger(record.N) && record.N > 1 ? record.N : SCRYPT_N;
    const r = Number.isInteger(record.r) && record.r > 0 ? record.r : SCRYPT_R;
    const p = Number.isInteger(record.p) && record.p > 0 ? record.p : SCRYPT_P;
    return { salt: salt, hash: hash, N: N, r: r, p: p };
  });
}

async function verifyPassword(record, password) {
  const derived = await scrypt(password, record.salt, record.hash.byteLength, { N: record.N, r: record.r, p: record.p, maxmem: SCRYPT_MAXMEM });
  return derived.byteLength === record.hash.byteLength && timingSafeEqual(derived, record.hash);
}

async function writePassword(file, password) {
  const salt = randomBytes(16);
  const hash = await scrypt(password, salt, SCRYPT_KEYLEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: SCRYPT_MAXMEM });
  const record = {
    version: 1,
    salt: base64url(salt),
    hash: base64url(hash),
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    updatedAt: new Date().toISOString(),
  };
  await mkdir(dirname(file), { recursive: true });
  const temporary = file + ".tmp-" + String(process.pid) + "-" + String(Date.now());
  await writeFile(temporary, JSON.stringify(record, null, 2) + "\n", { mode: 0o600 });
  await chmod(temporary, 0o600);
  await rename(temporary, file);
  await chmod(file, 0o600);
}

function normalizeOriginList(text) {
  const lines = String(text || "").split(/[\n,]+/u).map((line) => line.trim()).filter((line) => line.length > 0);
  const out = [];
  for (const line of lines) {
    if (originHost(line) === undefined) return { ok: false, reason: "无法解析的来源: " + line };
    out.push(line.replace(/\/+$/u, ""));
  }
  return { ok: true, value: out };
}

export function apply(ctx, config) {
  const options = { ...DEFAULTS, ...(config || {}) };
  const loginPath = normalizePath(options.path);
  const logoutPath = loginPath + "/logout";
  const apiStatePath = loginPath + "/api/state";
  const apiSettingsPath = loginPath + "/api/settings";
  const apiPasswordPath = loginPath + "/api/password";
  const indexPath = typeof options.indexPath === "string" && options.indexPath.startsWith("/") ? options.indexPath : "/index.html";
  // Only the SPA entry is shadowed. Everything else (assets, /api, the plugin's
  // own routes) keeps the host's own dispatch, and the index is re-read through
  // the webserver's fallback on indexPath — a path this plugin does not own.
  const documentPaths = indexPath === "/" ? [] : ["/"];
  if (loginPath === "/") throw new Error("dsh-password-login: path must not be the site root");
  const configMaxAgeDays = Math.max(1, Math.floor(Number(options.maxAgeDays) || 30));
  const failures = new Map();
  const events = [];

  function pushEvent(entry) {
    events.unshift({ at: new Date(), ...entry });
    if (events.length > 20) events.length = 20;
  }

  async function loadSettings() {
    const merged = { ...DEFAULT_SETTINGS, cookieMaxAgeDays: configMaxAgeDays };
    try {
      const text = await readFile(options.settingsFile, "utf8");
      const parsed = JSON.parse(text);
      if (parsed !== null && typeof parsed === "object") {
        if (CROSS_ORIGIN_MODES.includes(parsed.crossOrigin)) merged.crossOrigin = parsed.crossOrigin;
        if (Array.isArray(parsed.allowedOrigins)) merged.allowedOrigins = parsed.allowedOrigins.filter((item) => typeof item === "string" && item.length > 0);
        if (Number.isInteger(parsed.maxAttempts) && parsed.maxAttempts >= 1 && parsed.maxAttempts <= 100) merged.maxAttempts = parsed.maxAttempts;
        if (Number.isInteger(parsed.lockMinutes) && parsed.lockMinutes >= 1 && parsed.lockMinutes <= 1440) merged.lockMinutes = parsed.lockMinutes;
        if (Number.isInteger(parsed.cookieMaxAgeDays) && parsed.cookieMaxAgeDays >= 1 && parsed.cookieMaxAgeDays <= 3650) merged.cookieMaxAgeDays = parsed.cookieMaxAgeDays;
      }
    } catch {
      // missing or unreadable settings fall back to defaults
    }
    return merged;
  }

  async function saveSettings(next) {
    await mkdir(dirname(options.settingsFile), { recursive: true });
    const record = { version: 1, ...next, updatedAt: new Date().toISOString() };
    const temporary = options.settingsFile + ".tmp-" + String(process.pid) + "-" + String(Date.now());
    await writeFile(temporary, JSON.stringify(record, null, 2) + "\n", { mode: 0o600 });
    await chmod(temporary, 0o600);
    await rename(temporary, options.settingsFile);
    await chmod(options.settingsFile, 0o600);
  }

  async function currentSecret() {
    const record = await ctx.credentials.readRecord(SECRET_RECORD);
    if (record === undefined || record.kind !== "grant" || record.payload === null || typeof record.payload !== "object") return undefined;
    if (record.payload.version !== 1) return undefined;
    const secret = parseBase64url(record.payload.secret);
    return secret !== undefined && secret.byteLength === SECRET_BYTES ? secret : undefined;
  }

  /**
   * The browser's address. Behind the nginx front every socket peer is
   * 127.0.0.1, so the proxy's X-Forwarded-For is what distinguishes a real
   * local request from a LAN one — for rate limiting and for the settings page.
   */
  function clientKey(req) {
    const forwarded = req.headers["x-forwarded-for"];
    if (typeof forwarded === "string") {
      const first = forwarded.split(",")[0].trim();
      if (first.length > 0) return first;
    }
    return req.socket.remoteAddress || "unknown";
  }

  function isLoopback(req) {
    const address = clientKey(req).replace(/^::ffff:/u, "");
    return address === "127.0.0.1" || address === "::1";
  }

  function isLocked(key, now, limit) {
    const entry = failures.get(key);
    if (entry === undefined) return false;
    if (entry.resetAt <= now) {
      failures.delete(key);
      return false;
    }
    return entry.count >= limit;
  }

  function noteFailure(key, now, lockMs) {
    const entry = failures.get(key);
    if (entry === undefined || entry.resetAt <= now) {
      failures.set(key, { count: 1, resetAt: now + lockMs });
      return;
    }
    entry.count += 1;
  }

  function authenticated(cookieHeader, authority, secret) {
    const value = cookieFrom(cookieHeader, cookieName(authority));
    if (value === undefined) return false;
    const payload = decodeCookie(value, secret);
    return payload !== undefined && payload.authority === authority;
  }

  /**
   * Apply the cross-origin policy to a login POST.
   * strict    — the form must come from this very authority
   * allowlist — same as strict, plus the configured origins
   * off       — no origin/site inspection at all (password still required)
   */
  function checkOrigin(req, authority, settings, origin, site) {
    if (settings.crossOrigin === "off") return { ok: true };
    // "null" is what a browser sends for an opaque origin (sandboxed frame,
    // view-source, some embedded webviews). It carries no identity, so it is
    // treated like an absent Origin and Sec-Fetch-Site does the deciding.
    const known = typeof origin === "string" && origin.length > 0 && origin !== "null";
    const listed = Array.isArray(settings.allowedOrigins) ? settings.allowedOrigins : [];
    const allowListed = known && listed.some((entry) => {
      const trimmed = String(entry).replace(/\/+$/u, "");
      return trimmed === origin.replace(/\/+$/u, "") || originHost(trimmed) === originHost(origin);
    });
    if (site === "cross-site") {
      if (settings.crossOrigin === "allowlist" && allowListed) return { ok: true };
      return { ok: false, reason: "Sec-Fetch-Site: cross-site（来源 " + (origin || "未知") + "，目标 " + authority + "）" };
    }
    if (!known) return { ok: true, unknown: true };
    if (originHost(origin) === authority) return { ok: true };
    if (settings.crossOrigin === "allowlist" && allowListed) return { ok: true };
    return { ok: false, reason: "Origin " + origin + " 与本站 " + authority + " 不一致" };
  }

  function banner(message, notice) {
    if (message !== undefined) return '<div class="err">' + escapeHtml(message) + "</div>";
    if (notice !== undefined) return '<div class="ok">' + escapeHtml(notice) + "</div>";
    return "";
  }

  async function handleLogin(req, res, url, authority, secret, settings, method) {
    if (method === "GET") {
      const next = safeNext(url.searchParams.get("next") || "/");
      if (secret !== undefined && authenticated(req.headers.cookie, authority, secret)) {
        redirect(res, next);
        return;
      }
      const reason = url.searchParams.get("e");
      const message = reason === "1" ? "密码错误，请重试" : reason === "locked" ? "尝试次数过多，请稍后再试" : reason === "origin" ? url.searchParams.get("why") || "来源校验未通过" : undefined;
      send(res, 200, renderLogin(loginPath, message, next));
      return;
    }
    const check = checkOrigin(req, authority, settings, req.headers.origin, req.headers["sec-fetch-site"]);
    if (!check.ok) {
      pushEvent({ ip: clientKey(req), ok: false, detail: check.reason });
      ctx.logger.warn("password-login: origin=" + String(req.headers.origin) + " host=" + String(req.headers.host) + " site=" + String(req.headers["sec-fetch-site"]));
      send(res, 403, renderLogin(loginPath, "来源校验未通过：" + check.reason + "。可在 DSH 设置 → 登录安全 中调整跨站策略。"));
      return;
    }
    const now = Date.now();
    const key = clientKey(req);
    const lockMs = Math.max(1, settings.lockMinutes) * 60000;
    if (isLocked(key, now, settings.maxAttempts)) {
      pushEvent({ ip: key, ok: false, detail: "锁定中" });
      send(res, 429, renderLogin(loginPath, "尝试次数过多，请稍后再试"), { "retry-after": String(Math.ceil(lockMs / 1000)) });
      return;
    }
    const body = await readBody(req);
    if (body === undefined) {
      send(res, 413, renderLogin(loginPath, "请求体过大"));
      return;
    }
    const params = new URLSearchParams(body);
    const next = safeNext(params.get("next") || "/");
    const password = params.get("password") || "";
    if (password.length === 0 || password.length > 512) {
      redirect(res, loginPath + "?e=1&next=" + encodeURIComponent(next));
      return;
    }
    let record;
    try {
      record = await readPasswordRecord(options.passwordFile);
    } catch (error) {
      pushEvent({ ip: key, ok: false, detail: "密码文件不可用" });
      if (error && error.code === "ENOENT") {
        send(res, 503, renderLogin(loginPath, "尚未配置密码：请在服务器上运行 dsh-passwd 设置"));
        return;
      }
      send(res, 500, renderLogin(loginPath, "密码文件不可用"));
      return;
    }
    if (secret === undefined) {
      send(res, 500, renderLogin(loginPath, "服务器认证密钥不可用，请重启 dsh"));
      return;
    }
    let ok = false;
    try {
      ok = await verifyPassword(record, password);
    } catch {
      ok = false;
    }
    if (!ok) {
      noteFailure(key, Date.now(), lockMs);
      pushEvent({ ip: key, ok: false, detail: "密码错误" });
      redirect(res, loginPath + "?e=1&next=" + encodeURIComponent(next));
      return;
    }
    failures.delete(key);
    pushEvent({ ip: key, ok: true, detail: "来源 " + (req.headers.origin || "无 Origin") });
    const issuedAt = Date.now();
    const maxAgeMilliseconds = Math.max(1, settings.cookieMaxAgeDays) * DAY_MS;
    const expiresAt = issuedAt + maxAgeMilliseconds;
    const value = encodeCookie({ version: COOKIE_VERSION, authority: authority, issuedAt: issuedAt, expiresAt: expiresAt }, secret);
    ctx.logger.info("password-login: " + key + " authenticated for " + authority);
    redirect(res, next, { "set-cookie": sessionCookie(cookieName(authority), value, expiresAt, Math.floor(maxAgeMilliseconds / 1000), req.socket.encrypted === true) });
  }

  function sendJson(res, status, value) {
    res.writeHead(status, {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff",
    });
    res.end(JSON.stringify(value));
  }

  async function readJson(req) {
    const text = await readBody(req);
    if (text === undefined) return undefined;
    try {
      const value = JSON.parse(text);
      return value !== null && typeof value === "object" ? value : undefined;
    } catch {
      return undefined;
    }
  }

  /** JSON half consumed by the in-app settings section. */
  async function handleApi(req, res, url, authority, secret, method) {
    const signedIn = secret !== undefined && authenticated(req.headers.cookie, authority, secret);
    const pathname = url.pathname;
    if (method === "GET" && pathname === apiStatePath) {
      if (!signedIn) {
        sendJson(res, 401, { code: "unauthenticated", loginPath: loginPath });
        return;
      }
      const settings = await loadSettings();
      let passwordUpdatedAt;
      try {
        const info = await stat(options.passwordFile);
        passwordUpdatedAt = info.mtime.toLocaleString("sv-SE");
      } catch {
        passwordUpdatedAt = undefined;
      }
      sendJson(res, 200, {
        authenticated: true,
        settings: settings,
        events: events.map((entry) => ({ at: entry.at.toLocaleString("sv-SE"), ip: entry.ip, ok: entry.ok, detail: entry.detail || "" })),
        passwordUpdatedAt: passwordUpdatedAt,
        loginPath: loginPath,
        settingsFile: options.settingsFile,
        passwordFile: options.passwordFile,
      });
      return;
    }
    if (method !== "POST") {
      sendJson(res, 405, { code: "method-not-allowed" });
      return;
    }
    if (req.headers["sec-fetch-site"] === "cross-site") {
      sendJson(res, 403, { code: "cross-site" });
      return;
    }
    if (!signedIn) {
      sendJson(res, 401, { code: "unauthenticated", loginPath: loginPath });
      return;
    }
    const body = await readJson(req);
    if (body === undefined) {
      sendJson(res, 400, { code: "bad-body" });
      return;
    }
    if (pathname === apiSettingsPath) {
      const mode = body.crossOrigin;
      if (!CROSS_ORIGIN_MODES.includes(mode)) {
        sendJson(res, 400, { code: "bad-mode", message: "未知的跨站策略" });
        return;
      }
      const rawOrigins = Array.isArray(body.allowedOrigins) ? body.allowedOrigins.join("\n") : String(body.allowedOrigins || "");
      const origins = normalizeOriginList(rawOrigins);
      if (!origins.ok) {
        sendJson(res, 400, { code: "bad-origin", message: origins.reason });
        return;
      }
      const current = await loadSettings();
      const number = (value, min, max, fallback) => (Number.isInteger(value) && value >= min && value <= max ? value : fallback);
      const next = {
        version: 1,
        crossOrigin: mode,
        allowedOrigins: origins.value,
        maxAttempts: number(body.maxAttempts, 1, 100, current.maxAttempts),
        lockMinutes: number(body.lockMinutes, 1, 1440, current.lockMinutes),
        cookieMaxAgeDays: number(body.cookieMaxAgeDays, 1, 3650, current.cookieMaxAgeDays),
      };
      await saveSettings(next);
      pushEvent({ ip: clientKey(req), ok: true, detail: "设置已保存（" + mode + "）" });
      ctx.logger.info("password-login: settings saved (" + mode + ")");
      sendJson(res, 200, { ok: true, settings: next });
      return;
    }
    if (pathname === apiPasswordPath) {
      const next = typeof body.next === "string" ? body.next : "";
      const confirm = typeof body.confirm === "string" ? body.confirm : "";
      if (next.length < 8) {
        sendJson(res, 400, { code: "too-short", message: "新密码至少 8 位" });
        return;
      }
      if (next !== confirm) {
        sendJson(res, 400, { code: "mismatch", message: "两次输入的新密码不一致" });
        return;
      }
      await writePassword(options.passwordFile, next);
      failures.clear();
      pushEvent({ ip: clientKey(req), ok: true, detail: "密码已更新" });
      sendJson(res, 200, { ok: true, passwordUpdatedAt: new Date().toLocaleString("sv-SE") });
      return;
    }
    sendJson(res, 404, { code: "not-found" });
  }

  /** The launch token the host minted for this process, read through its own URL helper. */
  function expectedLaunchToken() {
    try {
      const url = new URL(ctx.connection.authenticatedUrl("http://dsh.invalid/"));
      return url.searchParams.get("token") || undefined;
    } catch {
      return undefined;
    }
  }

  function tokenMatches(actual, expected) {
    const left = Buffer.from(actual, "utf8");
    const right = Buffer.from(expected, "utf8");
    return left.byteLength === right.byteLength && timingSafeEqual(left, right);
  }

  /** Re-serve the real index through the webserver's resource path (no browser auth there). */
  async function serveIndex(req, res, host, secure) {
    const target = (secure ? "https:" : "http:") + "//" + host + indexPath;
    const request = new Request(target, { method: req.method === "HEAD" ? "HEAD" : "GET", headers: req.headers });
    const response = await ctx.webServer.readResource(request, ctx.connection.browserPeer);
    const headers = {};
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });
    res.writeHead(response.status, headers);
    if (response.body === null) {
      res.end();
      return;
    }
    for await (const chunk of response.body) {
      if (!res.write(chunk)) await new Promise((resolve) => res.once("drain", resolve));
    }
    res.end();
  }

  /**
   * Own the document request so the password door lives in the plugin:
   * a launch-token URL exchanges for the cookie exactly like the host does,
   * an authenticated request gets the real index, and everyone else is
   * redirected to the login page instead of the host's plain 401.
   */
  async function handleDocument(req, res, url, authority, secret, secure, host) {
    const method = req.method || "GET";
    if (method !== "GET" && method !== "HEAD") {
      res.writeHead(405, { allow: "GET, HEAD" });
      res.end();
      return;
    }
    if (authority === undefined) {
      send(res, 400, "bad host\n", { "content-type": "text/plain; charset=utf-8" });
      return;
    }
    const tokens = url.searchParams.getAll("token");
    if (tokens.length > 0) {
      const expected = expectedLaunchToken();
      const sameToken = tokens.length === 1 && expected !== undefined && tokenMatches(tokens.join(""), expected);
      if (method === "GET" && url.pathname === "/" && sameToken && secret !== undefined) {
        const settings = await loadSettings();
        const issuedAt = Date.now();
        const maxAge = Math.max(1, settings.cookieMaxAgeDays) * DAY_MS;
        const expiresAt = issuedAt + maxAge;
        const value = encodeCookie({ version: COOKIE_VERSION, authority: authority, issuedAt: issuedAt, expiresAt: expiresAt }, secret);
        redirect(res, "./", { "set-cookie": sessionCookie(cookieName(authority), value, expiresAt, Math.floor(maxAge / 1000), secure) });
        return;
      }
      if (method === "GET" && url.pathname === "/" && secret !== undefined && authenticated(req.headers.cookie, authority, secret)) {
        redirect(res, "./");
        return;
      }
      send(res, 401, "dsh web authentication required; reopen the URL printed by dsh web.\n", { "content-type": "text/plain; charset=utf-8" });
      return;
    }
    if (secret !== undefined && authenticated(req.headers.cookie, authority, secret)) {
      await serveIndex(req, res, host, secure);
      return;
    }
    const next = url.pathname + url.search;
    redirect(res, loginPath + "?next=" + encodeURIComponent(next === "/" ? "/" : next));
  }

  async function handler(req, res) {
    const secure = ctx.webServer.protocol === "https:";
    const host = req.headers.host;
    const authority = audienceOf(host, secure);
    const requestUrl = new URL(req.url || "/", (secure ? "https:" : "http:") + "//" + (host || "dsh.invalid"));
    const method = req.method || "GET";
    const pathname = requestUrl.pathname;
    const apiPaths = [apiStatePath, apiSettingsPath, apiPasswordPath];
    if (pathname !== loginPath && pathname !== logoutPath && !apiPaths.includes(pathname) && !documentPaths.includes(pathname)) {
      send(res, 404, "not found\n", { "content-type": "text/plain; charset=utf-8" });
      return;
    }
    if (method !== "GET" && method !== "POST") {
      send(res, 405, "method not allowed\n", { "content-type": "text/plain; charset=utf-8", allow: "GET, POST" });
      return;
    }
    if (authority === undefined) {
      send(res, 400, "bad host\n", { "content-type": "text/plain; charset=utf-8" });
      return;
    }
    const secret = await currentSecret();
    if (pathname === logoutPath) {
      if (method !== "GET") {
        send(res, 405, "method not allowed\n", { "content-type": "text/plain; charset=utf-8", allow: "GET" });
        return;
      }
      redirect(res, loginPath, { "set-cookie": sessionCookie(cookieName(authority), "", Date.now() - DAY_MS, 0, secure) });
      return;
    }
    if (documentPaths.includes(pathname)) {
      await handleDocument(req, res, requestUrl, authority, secret, secure, host);
      return;
    }
    if (apiPaths.includes(pathname)) {
      await handleApi(req, res, requestUrl, authority, secret, method);
      return;
    }
    const settings = await loadSettings();
    await handleLogin(req, res, requestUrl, authority, secret, settings, method);
  }

  ctx.effect(() => {
    const disposers = [loginPath, logoutPath, apiStatePath, apiSettingsPath, apiPasswordPath, ...documentPaths].map((path) => ctx.webServer.register({ kind: "exact", path: path, handler: handler }));
    return () => {
      for (const dispose of disposers.reverse()) dispose();
    };
  });
}
