/**
 * Market IQ — Single-file Cloudflare Worker (index.js)
 * ---------------------------------------------------
 * ✅ Telegram Bot (Webhook /telegram) + KV + Cron + Admin Panel + MiniApp (root) + Owner panel
 * ✅ No-crash design: webhook replies immediately "ok" and processes in ctx.waitUntil
 * ✅ All fetch calls use fetchWithTimeout + catch (no timeout/crash)
 * ✅ RBAC: OWNER_IDS / ADMIN_IDS (Owner always Admin)
 * ✅ Payments: USDT (BEP20) via /tx, pending list, approve/reject + alarms
 * ✅ Onboarding: name + Share Contact + unique phone protection + profile/settings persist
 * ✅ Signals: Market -> Symbol (popular or custom typing) + progress edit 1/3 2/3 3/3 + chart zones
 * ✅ Strict zones_v1 schema with JSON repair (once) + validation
 * ✅ News: RSS + 10m cache + scoring relevance/impact/recency + Forex calendar filter + Persian summary (AI if available)
 * ✅ MiniApp: root "/" HTML + APIs /api/profile /api/settings /api/signals /api/news /api/wallet /api/requests
 * ✅ Admin Panel: /admin HTML + APIs /api/admin/*
 * ✅ Support Tickets: /support -> staff notify + visible/reply in panel
 * ✅ Requests: deposit/withdraw + staff notify + panel workflow
 * ✅ Quota: Free daily/monthly, Sub daily, staff unlimited + progress bars
 * ✅ Custom prompt: /customprompt -> generate now, deliver after 2h via Cron queue (style CUSTOM only after delivery)
 * ✅ Improvements implemented: rate limit, dedupe update_id, circuit breaker, audit log, reports, masking PII, export pages, broadcast job, ban/unban, config versioning+rollback
 *
 * Bindings expected:
 * - env.BOT_KV (KV namespace binding)
 * - env.AI (optional Cloudflare AI binding)
 *
 * Required ENV:
 * - BOT_TOKEN
 * - TELEGRAM_SECRET_TOKEN
 * - BOT_NAME=Market IQ
 * - OWNER_IDS=... (comma/space separated)
 * - ADMIN_IDS=... (comma/space separated)
 * - BOT_PUBLIC_WALLET=... (fallback if KV config wallet not set)
 *
 * Optional ENV:
 * - WEBHOOK_URL (for /setwebhook)
 * - ADMIN_BEARER_TOKEN (to access admin panel outside Telegram)
 * - AI_PROVIDER=openai|gemini|compat|cloudflare
 * - OPENAI_API_KEY, OPENAI_MODEL
 * - GEMINI_API_KEY, GEMINI_MODEL
 * - AI_COMPAT_BASE_URL, AI_COMPAT_API_KEY, AI_COMPAT_MODEL
 * - Data provider keys: TWELVEDATA_API_KEY, FINNHUB_API_KEY, ALPHAVANTAGE_API_KEY, POLYGON_API_KEY
 * - Limits/points defaults: FREE_DAILY_LIMIT, FREE_MONTHLY_LIMIT, SUB_DAILY_LIMIT, SUB_PRICE_USDT, SUB_DURATION_DAYS
 * - REF_POINTS_PER_INVITE, REF_POINTS_REDEEM_FREE_SUB, REF_POINTS_BUY_SUB, REF_COMMISSION_STEP_PCT, REF_COMMISSION_MAX_PCT
 */

const VERSION = "marketiq-indexjs-2026.02.07";
const KV_PREFIX = "marketiq:";
const DEFAULT_TIMEOUT_MS = 12000;

// ========== Utilities ==========
const nowMs = () => Date.now();
const toStr = (x) => (x === undefined || x === null ? "" : String(x));
const trunc = (s, n = 1800) => {
  s = String(s || "");
  return s.length > n ? s.slice(0, Math.max(0, n - 3)) + "..." : s;
};
const clamp = (n, a, b) => Math.max(a, Math.min(b, n));
const pad2 = (n) => String(n).padStart(2, "0");
const utcDateKey = (d = new Date()) => `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}`;
const utcMonthKey = (d = new Date()) => `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}`;
const safeParseInt = (v, def = 0) => {
  const n = Number.parseInt(String(v ?? ""), 10);
  return Number.isFinite(n) ? n : def;
};
const safeParseFloat = (v, def = 0) => {
  const n = Number.parseFloat(String(v ?? ""));
  return Number.isFinite(n) ? n : def;
};
function parseIdSet(str) {
  const s = toStr(str).trim();
  if (!s) return new Set();
  const parts = s.split(/[\s,]+/g).map((p) => p.trim()).filter(Boolean);
  const out = new Set();
  for (const p of parts) if (/^\d+$/.test(p)) out.add(p);
  return out;
}
function botName(env) {
  const s = toStr(env.BOT_NAME).trim();
  return s || "Market IQ";
}
function randomToken(len = 16) {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const a = new Uint8Array(len);
  crypto.getRandomValues(a);
  let s = "";
  for (let i = 0; i < a.length; i++) s += chars[a[i] % chars.length];
  return s;
}
function bytesToHex(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = "";
  for (let i = 0; i < arr.length; i++) out += arr[i].toString(16).padStart(2, "0");
  return out;
}
async function sha256Hex(text) {
  const enc = new TextEncoder().encode(String(text || ""));
  const dig = await crypto.subtle.digest("SHA-256", enc);
  return bytesToHex(new Uint8Array(dig));
}
function normalizePhone(phone) {
  const p = String(phone || "").trim();
  if (!p) return "";
  let x = p.replace(/[^\d+]/g, "");
  if (x.startsWith("00")) x = "+" + x.slice(2);
  if (!x.startsWith("+") && x.length >= 10) x = "+" + x;
  return x;
}
function maskPhone(phone) {
  const p = normalizePhone(phone);
  if (!p) return "";
  const digits = p.replace(/[^\d]/g, "");
  if (digits.length < 6) return "***";
  const head = digits.slice(0, 3);
  const tail = digits.slice(-2);
  return `+${head}***${tail}`;
}
function normalizeSymbolInput(t) {
  const s = String(t || "").trim().toUpperCase();
  if (!s) return "";
  const clean = s.replace(/[^A-Z0-9=.^:-]/g, "");
  if (clean.length < 2 || clean.length > 24) return "";
  return clean;
}
function ensureBackHint(msg) {
  return `${msg}\n\n⬅️ برای برگشت: /menu`;
}

// ========== Safe fetch ==========
async function fetchWithTimeout(input, init = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(input, { ...init, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(t);
  }
}
async function safeJson(res) {
  try {
    return await res.json();
  } catch {
    return null;
  }
}
async function safeText(res) {
  try {
    return await res.text();
  } catch {
    return "";
  }
}
async function promiseWithTimeout(promise, timeoutMs, label = "timeout") {
  let t;
  const timeout = new Promise((_, rej) => {
    t = setTimeout(() => rej(new Error(label)), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(t));
}

// ========== KV Keys ==========
const kConfig = () => `${KV_PREFIX}config`;
const kConfigVer = (ts, rand) => `${KV_PREFIX}config:ver:${String(ts).padStart(14, "0")}:${rand}`;
const kAudit = (ts, rand) => `${KV_PREFIX}audit:${String(ts).padStart(14, "0")}:${rand}`;
const kAuditIdx = (ts, rand) => `${KV_PREFIX}auditidx:${String(ts).padStart(14, "0")}:${rand}`;
const kUser = (id) => `${KV_PREFIX}user:${id}`;
const kRefCode = (code) => `${KV_PREFIX}refcode:${code}`;
const kPhoneHash = (hash) => `${KV_PREFIX}phone:${hash}`;
const kPayment = (txid) => `${KV_PREFIX}payment:${txid}`;
const kPayIdx = (status, ts, txid) => `${KV_PREFIX}pidx:${status}:${String(ts).padStart(14, "0")}:${txid}`;
const kTicket = (id) => `${KV_PREFIX}ticket:${id}`;
const kTicketIdx = (status, ts, id) => `${KV_PREFIX}tidx:${status}:${String(ts).padStart(14, "0")}:${id}`;
const kRequest = (id) => `${KV_PREFIX}req:${id}`;
const kRequestIdx = (status, ts, id) => `${KV_PREFIX}ridx:${status}:${String(ts).padStart(14, "0")}:${id}`;
const kTask = (ts, kind, userId, rand) => `${KV_PREFIX}task:${String(ts).padStart(14, "0")}:${kind}:${userId}:${rand}`;
const kTaskIdx = () => `${KV_PREFIX}task:`;
const kNewsCache = (tag) => `${KV_PREFIX}news:${tag}`;
const kDedupeUpdate = (updateId) => `${KV_PREFIX}upd:${updateId}`;
const kRateLimit = (scope, who, windowKey) => `${KV_PREFIX}rl:${scope}:${who}:${windowKey}`;
const kCircuit = (name) => `${KV_PREFIX}cb:${name}`;
const kMetricDay = (dayKey) => `${KV_PREFIX}m:day:${dayKey}`;
const kActiveDayUser = (dayKey, userId) => `${KV_PREFIX}active:${dayKey}:${userId}`;
const kBroadcastJob = (jobId) => `${KV_PREFIX}job:broadcast:${jobId}`;

// ========== KV helpers ==========
async function kvGetJson(env, key) {
  try {
    return await env.BOT_KV.get(key, "json");
  } catch (e) {
    console.error("KV get json error", key, e);
    return null;
  }
}
async function kvPutJson(env, key, obj, opts = undefined) {
  try {
    await env.BOT_KV.put(key, JSON.stringify(obj), opts);
    return true;
  } catch (e) {
    console.error("KV put json error", key, e);
    return false;
  }
}
async function kvPutText(env, key, text, opts = undefined) {
  try {
    await env.BOT_KV.put(key, String(text), opts);
    return true;
  } catch (e) {
    console.error("KV put text error", key, e);
    return false;
  }
}
async function kvDel(env, key) {
  try {
    await env.BOT_KV.delete(key);
    return true;
  } catch (e) {
    console.error("KV delete error", key, e);
    return false;
  }
}
async function kvList(env, prefix, limit = 100, cursor = undefined) {
  try {
    return await env.BOT_KV.list({ prefix, limit, cursor });
  } catch (e) {
    console.error("KV list error", prefix, e);
    return { keys: [], cursor: "" };
  }
}

// ========== RBAC ==========
function isOwnerId(env, userId) {
  const id = String(userId);
  return parseIdSet(env.OWNER_IDS).has(id);
}
function isAdminId(env, userId) {
  const id = String(userId);
  if (isOwnerId(env, id)) return true;
  return parseIdSet(env.ADMIN_IDS).has(id);
}
function roleOf(env, userId) {
  if (isOwnerId(env, userId)) return "owner";
  if (isAdminId(env, userId)) return "admin";
  return "user";
}

// ========== Defaults / Config ==========
function defaultConfig(env) {
  const freeDaily = safeParseInt(env.FREE_DAILY_LIMIT, 50);
  const freeMonthly = safeParseInt(env.FREE_MONTHLY_LIMIT, 500);
  const subDaily = safeParseInt(env.SUB_DAILY_LIMIT, 50);

  const subPrice = safeParseFloat(env.SUB_PRICE_USDT, 2);
  const subDays = safeParseInt(env.SUB_DURATION_DAYS, 30);

  const pointsPerInvite = safeParseInt(env.REF_POINTS_PER_INVITE, 6);
  const redeemFreeSub = safeParseInt(env.REF_POINTS_REDEEM_FREE_SUB, 500);
  const buySub = safeParseInt(env.REF_POINTS_BUY_SUB, 1000);

  const stepPct = safeParseInt(env.REF_COMMISSION_STEP_PCT, 4);
  const maxPct = safeParseInt(env.REF_COMMISSION_MAX_PCT, 20);

  return {
    version: 2,
    updatedAt: nowMs(),
    // wallet stored in KV config, fallback to env.BOT_PUBLIC_WALLET
    walletPublic: toStr(env.BOT_PUBLIC_WALLET).trim() || "",
    subscription: {
      priceUSDT: Math.max(0.1, subPrice),
      durationDays: Math.max(1, subDays),
      dailyLimit: Math.max(1, subDaily)
    },
    limits: {
      freeDaily: Math.max(1, freeDaily),
      freeMonthly: Math.max(Math.max(1, freeDaily), Math.max(1, freeMonthly))
    },
    points: {
      perInvite: Math.max(0, pointsPerInvite),
      redeemFreeSub: Math.max(1, redeemFreeSub),
      buySub: Math.max(1, buySub)
    },
    commission: {
      stepPct: clamp(stepPct, 0, 50),
      maxPct: clamp(maxPct, 0, 50)
    },
    banner: {
      enabled: true,
      text: "🎁 پیشنهاد ویژه: با اشتراک Market IQ حرفه‌ای شو!",
      link: "https://t.me/"
    },
    styles: {
      RTM: { enabled: true, label: "RTM" },
      ICT: { enabled: true, label: "ICT" },
      PRICE_ACTION: { enabled: true, label: "Price Action" },
      GENERAL: { enabled: true, label: "General Prompt" },
      METHOD: { enabled: true, label: "Method" },
      CUSTOM: { enabled: true, label: "Custom Prompt" }
    },
    prompts: {
      base:
        "You are Market IQ, a professional market analyst. Provide structured analysis in Persian. Include bias, structure, key levels, zones, scenarios, invalidation, risk management, and an actionable plan.",
      vision:
        "You are Market IQ Vision. Analyze the given chart image and return concise observations and zone confirmations in Persian.",
      perStyle: {
        RTM: "Use RTM logic: origin/base/impulse, fresh zones, clear invalidation, and risk plan.",
        ICT: "Use ICT concepts: liquidity, order blocks, FVG, session bias, and clear invalidation.",
        PRICE_ACTION: "Use pure price action: market structure, S/R, momentum, and clear invalidation.",
        GENERAL: "General multi-factor technical analysis with clear invalidation.",
        METHOD: "Follow method: data -> bias -> setup -> risk -> plan. Keep it practical.",
        CUSTOM: "Use the user's custom strategy prompt if available; otherwise use GENERAL."
      }
    },
    news: {
      enabledDefault: true,
      ttlMs: 10 * 60 * 1000,
      // You can edit these in config via /admin (owner-only recommended)
      rss: [
        "https://www.coindesk.com/arc/outboundfeeds/rss/",
        "https://cointelegraph.com/rss",
        "https://www.reuters.com/rssFeed/marketsNews",
        "https://feeds.finance.yahoo.com/rss/2.0/headline?s=%5EGSPC&region=US&lang=en-US",
        "https://www.fxstreet.com/rss/news"
      ],
      noiseFilters: [
        "weekly recap",
        "market wrap",
        "what to watch",
        "sponsored",
        "top ",
        "morning news",
        "afternoon news",
        "evening news",
        "recap",
        "roundup"
      ],
      forexCalendar: {
        enabled: true,
        sources: ["https://nfs.faireconomy.media/ff_calendar_thisweek.json"]
      }
    },
    features: {
      chartEnabled: true,
      newsEnabled: true,
      visionEnabled: false, // optional
      broadcastEnabled: true
    },
    security: {
      // basic rate limits (best-effort; KV not atomic)
      rlWebhookPerMin: 60, // per user
      rlAnalyzePerMin: 8, // per user (miniapp/api + telegram)
      rlAdminPerMin: 120
    }
  };
}

function normalizeConfig(env, cfg) {
  const d = defaultConfig(env);
  const out = {
    ...d,
    ...(cfg && typeof cfg === "object" ? cfg : {}),
    subscription: { ...d.subscription, ...(cfg?.subscription || {}) },
    limits: { ...d.limits, ...(cfg?.limits || {}) },
    points: { ...d.points, ...(cfg?.points || {}) },
    commission: { ...d.commission, ...(cfg?.commission || {}) },
    banner: { ...d.banner, ...(cfg?.banner || {}) },
    styles: { ...d.styles, ...(cfg?.styles || {}) },
    prompts: {
      ...d.prompts,
      ...(cfg?.prompts || {}),
      perStyle: { ...d.prompts.perStyle, ...(cfg?.prompts?.perStyle || {}) }
    },
    news: {
      ...d.news,
      ...(cfg?.news || {}),
      forexCalendar: { ...d.news.forexCalendar, ...(cfg?.news?.forexCalendar || {}) }
    },
    features: { ...d.features, ...(cfg?.features || {}) },
    security: { ...d.security, ...(cfg?.security || {}) }
  };

  out.updatedAt = nowMs();
  out.subscription.priceUSDT = Math.max(0.1, Number(out.subscription.priceUSDT || d.subscription.priceUSDT));
  out.subscription.durationDays = Math.max(1, safeParseInt(out.subscription.durationDays, d.subscription.durationDays));
  out.subscription.dailyLimit = Math.max(1, safeParseInt(out.subscription.dailyLimit, d.subscription.dailyLimit));

  out.limits.freeDaily = Math.max(1, safeParseInt(out.limits.freeDaily, d.limits.freeDaily));
  out.limits.freeMonthly = Math.max(out.limits.freeDaily, safeParseInt(out.limits.freeMonthly, d.limits.freeMonthly));

  out.points.perInvite = Math.max(0, safeParseInt(out.points.perInvite, d.points.perInvite));
  out.points.redeemFreeSub = Math.max(1, safeParseInt(out.points.redeemFreeSub, d.points.redeemFreeSub));
  out.points.buySub = Math.max(1, safeParseInt(out.points.buySub, d.points.buySub));

  out.commission.stepPct = clamp(safeParseInt(out.commission.stepPct, d.commission.stepPct), 0, 50);
  out.commission.maxPct = clamp(safeParseInt(out.commission.maxPct, d.commission.maxPct), 0, 50);

  out.banner.enabled = !!out.banner.enabled;
  out.features.chartEnabled = !!out.features.chartEnabled;
  out.features.newsEnabled = !!out.features.newsEnabled;
  out.features.visionEnabled = !!out.features.visionEnabled;
  out.features.broadcastEnabled = !!out.features.broadcastEnabled;

  out.security.rlWebhookPerMin = clamp(safeParseInt(out.security.rlWebhookPerMin, d.security.rlWebhookPerMin), 10, 600);
  out.security.rlAnalyzePerMin = clamp(safeParseInt(out.security.rlAnalyzePerMin, d.security.rlAnalyzePerMin), 1, 120);
  out.security.rlAdminPerMin = clamp(safeParseInt(out.security.rlAdminPerMin, d.security.rlAdminPerMin), 10, 1000);

  // Ensure CUSTOM style exists
  if (!out.styles.CUSTOM) out.styles.CUSTOM = { enabled: true, label: "Custom Prompt" };
  if (!out.prompts.perStyle.CUSTOM) out.prompts.perStyle.CUSTOM = d.prompts.perStyle.CUSTOM;

  return out;
}

const CONFIG_CACHE = { ts: 0, cfg: null };

async function loadConfig(env) {
  const fresh = 25_000;
  if (CONFIG_CACHE.cfg && nowMs() - CONFIG_CACHE.ts < fresh) return CONFIG_CACHE.cfg;

  const raw = await kvGetJson(env, kConfig());
  const cfg = normalizeConfig(env, raw || {});
  CONFIG_CACHE.cfg = cfg;
  CONFIG_CACHE.ts = nowMs();
  return cfg;
}

async function auditLog(env, actorId, action, beforeObj, afterObj, meta = {}) {
  try {
    const ts = nowMs();
    const rand = randomToken(6);
    const entry = {
      ts,
      actorId: String(actorId || ""),
      action: String(action || ""),
      beforeHash: beforeObj ? await sha256Hex(JSON.stringify(beforeObj)) : "",
      afterHash: afterObj ? await sha256Hex(JSON.stringify(afterObj)) : "",
      meta: meta || {}
    };
    await kvPutJson(env, kAudit(ts, rand), entry);
    await kvPutText(env, kAuditIdx(ts, rand), "1");
  } catch (e) {
    console.error("auditLog error", e);
  }
}

async function saveConfig(env, actorId, newCfg, reason = "config_update") {
  const oldCfg = await loadConfig(env);

  // versioning snapshot (store old config)
  const verKey = kConfigVer(nowMs(), randomToken(4));
  await kvPutJson(env, verKey, oldCfg);

  const normalized = normalizeConfig(env, newCfg || {});
  await kvPutJson(env, kConfig(), normalized);
  CONFIG_CACHE.cfg = normalized;
  CONFIG_CACHE.ts = nowMs();

  await auditLog(env, actorId, reason, oldCfg, normalized, { verKey });

  return normalized;
}

// Patch config with RBAC: Admin may change operational things; Owner may change everything.
function applyConfigPatchWithRBAC(env, role, cfg, patch) {
  const cur = normalizeConfig(env, cfg || {});
  const next = JSON.parse(JSON.stringify(cur));

  const isOwner = role === "owner";
  const isAdmin = role === "admin" || role === "owner";

  if (!patch || typeof patch !== "object") return next;

  // Admin allowed: limits, banner, subscription price/duration/dailyLimit (operational), feature flags (some), security (limited)
  // Owner-only: walletPublic, points rules, commission rules, prompts, styles, rss sources/noiseFilters, security advanced
  const ownerOnly = new Set([
    "walletPublic",
    "points",
    "commission",
    "prompts",
    "styles",
    "news"
  ]);

  for (const key of Object.keys(patch)) {
    if (ownerOnly.has(key) && !isOwner) continue;
    if (key === "subscription" && !isAdmin) continue;
    if (key === "limits" && !isAdmin) continue;
    if (key === "banner" && !isAdmin) continue;
    if (key === "features" && !isAdmin) continue;
    if (key === "security" && !isOwner) continue; // security owner-only

    // Apply
    if (key === "walletPublic") next.walletPublic = String(patch.walletPublic || "").trim();
    else if (key === "subscription") next.subscription = { ...next.subscription, ...(patch.subscription || {}) };
    else if (key === "limits") next.limits = { ...next.limits, ...(patch.limits || {}) };
    else if (key === "banner") next.banner = { ...next.banner, ...(patch.banner || {}) };
    else if (key === "features") next.features = { ...next.features, ...(patch.features || {}) };
    else if (key === "security") next.security = { ...next.security, ...(patch.security || {}) };
    else if (key === "points") next.points = { ...next.points, ...(patch.points || {}) };
    else if (key === "commission") next.commission = { ...next.commission, ...(patch.commission || {}) };
    else if (key === "news") {
      next.news = { ...next.news, ...(patch.news || {}) };
      if (patch.news?.forexCalendar) next.news.forexCalendar = { ...next.news.forexCalendar, ...(patch.news.forexCalendar || {}) };
    } else if (key === "prompts") {
      next.prompts = { ...next.prompts, ...(patch.prompts || {}) };
      if (patch.prompts?.perStyle) next.prompts.perStyle = { ...next.prompts.perStyle, ...(patch.prompts.perStyle || {}) };
    } else if (key === "styles") {
      next.styles = { ...next.styles, ...(patch.styles || {}) };
    }
  }

  return normalizeConfig(env, next);
}

async function rollbackConfig(env, actorId, verKey) {
  const role = roleOf(env, actorId);
  if (role !== "owner") return { ok: false, error: "owner_only" };

  const snap = await kvGetJson(env, verKey);
  if (!snap) return { ok: false, error: "version_not_found" };

  const saved = await saveConfig(env, actorId, snap, "config_rollback");
  return { ok: true, cfg: saved };
}

// ========== User model ==========
function defaultUser(id) {
  const createdAt = nowMs();
  const referralCode = randomToken(8);
  return {
    id: String(id),
    createdAt,
    lastSeenAt: 0,
    moderation: {
      bannedUntil: 0,
      banReason: "",
      phoneDuplicate: false
    },
    profile: {
      onboardingDone: false,
      name: "",
      phone: "",
      experience: "",
      favoriteMarket: ""
    },
    settings: {
      tf: "H1",
      risk: "متوسط",
      style: "GENERAL",
      news: true
    },
    quota: {
      dayKey: utcDateKey(),
      dayUsed: 0,
      monthKey: utcMonthKey(),
      monthUsed: 0
    },
    referral: {
      code: referralCode,
      referredBy: "",
      invites: 0,
      successfulInvites: 0,
      points: 0,
      commissionPct: 0
    },
    wallet: { bep20: "" },
    subscription: {
      active: false,
      until: 0,
      plan: "FREE",
      dailyLimit: 0
    },
    payments: {
      submittedTxids: [],
      lastTxAt: 0
    },
    customPrompt: {
      ready: false,
      prompt: "",
      requestedAt: 0,
      deliverAt: 0
    },
    state: {
      flow: "idle",
      data: {}
    },
    stats: {
      analysisCount: 0,
      lastAnalysisAt: 0
    }
  };
}

async function ensureUser(env, userId) {
  const id = String(userId);
  let u = await kvGetJson(env, kUser(id));
  if (!u || typeof u !== "object") {
    u = defaultUser(id);
    // index referral code
    await kvPutText(env, kRefCode(u.referral.code), id, { expirationTtl: 365 * 24 * 3600 });
    // metrics: new user
    await metricInc(env, "newUsers", 1);
  }

  // Ensure referral code mapping exists
  if (!u.referral?.code) {
    u.referral = { ...(u.referral || {}), code: randomToken(8) };
    await kvPutText(env, kRefCode(u.referral.code), id, { expirationTtl: 365 * 24 * 3600 });
  } else {
    const mapped = await env.BOT_KV.get(kRefCode(u.referral.code));
    if (!mapped) await kvPutText(env, kRefCode(u.referral.code), id, { expirationTtl: 365 * 24 * 3600 });
  }

  // Fix missing structures
  if (!u.moderation) u.moderation = { bannedUntil: 0, banReason: "", phoneDuplicate: false };
  if (!u.profile) u.profile = { onboardingDone: false, name: "", phone: "", experience: "", favoriteMarket: "" };
  if (!u.settings) u.settings = { tf: "H1", risk: "متوسط", style: "GENERAL", news: true };
  if (!u.quota) u.quota = { dayKey: utcDateKey(), dayUsed: 0, monthKey: utcMonthKey(), monthUsed: 0 };
  if (!u.referral) u.referral = { code: randomToken(8), referredBy: "", invites: 0, successfulInvites: 0, points: 0, commissionPct: 0 };
  if (!u.wallet) u.wallet = { bep20: "" };
  if (!u.subscription) u.subscription = { active: false, until: 0, plan: "FREE", dailyLimit: 0 };
  if (!u.payments) u.payments = { submittedTxids: [], lastTxAt: 0 };
  if (!u.customPrompt) u.customPrompt = { ready: false, prompt: "", requestedAt: 0, deliverAt: 0 };
  if (!u.state) u.state = { flow: "idle", data: {} };
  if (!u.stats) u.stats = { analysisCount: 0, lastAnalysisAt: 0 };

  // Expire subscription if needed
  if (u.subscription?.active && u.subscription.until && nowMs() > u.subscription.until) {
    u.subscription.active = false;
    u.subscription.plan = "FREE";
  }

  // Reset quota keys
  if (u.quota.dayKey !== utcDateKey()) {
    u.quota.dayKey = utcDateKey();
    u.quota.dayUsed = 0;
  }
  if (u.quota.monthKey !== utcMonthKey()) {
    u.quota.monthKey = utcMonthKey();
    u.quota.monthUsed = 0;
  }

  // Update lastSeen & active DAU (dedup)
  const dayKey = utcDateKey();
  u.lastSeenAt = nowMs();
  await markActiveAndMetric(env, dayKey, id);

  await saveUser(env, u);
  return u;
}

async function saveUser(env, user) {
  try {
    await env.BOT_KV.put(kUser(user.id), JSON.stringify(user));
  } catch (e) {
    console.error("saveUser error", e);
  }
}

function styleLabel(cfg, styleKey) {
  const key = String(styleKey || "").toUpperCase();
  const s = cfg?.styles?.[key];
  return s?.label || key;
}
function availableStylesForUser(cfg, user) {
  const out = [];
  const styles = cfg?.styles || {};
  for (const k of Object.keys(styles)) {
    if (!styles[k]?.enabled) continue;
    if (k === "CUSTOM" && !user.customPrompt?.ready) continue; // required
    out.push(k);
  }
  const order = ["RTM", "ICT", "PRICE_ACTION", "GENERAL", "METHOD", "CUSTOM"];
  out.sort((a, b) => order.indexOf(a) - order.indexOf(b));
  return out;
}

// ========== Moderation ==========
function isBanned(user) {
  const until = Number(user?.moderation?.bannedUntil || 0);
  return until > nowMs();
}

// ========== Metrics ==========
async function metricInc(env, field, delta) {
  const dayKey = utcDateKey();
  const key = kMetricDay(dayKey);
  const obj = (await kvGetJson(env, key)) || { dayKey, ts: nowMs(), counters: {} };
  obj.ts = nowMs();
  obj.counters = obj.counters || {};
  obj.counters[field] = (safeParseInt(obj.counters[field], 0) + delta);
  // Keep metrics 90 days
  await kvPutJson(env, key, obj, { expirationTtl: 90 * 24 * 3600 });
}
async function markActiveAndMetric(env, dayKey, userId) {
  const k = kActiveDayUser(dayKey, userId);
  try {
    const existing = await env.BOT_KV.get(k);
    if (existing) return;
    await env.BOT_KV.put(k, "1", { expirationTtl: 2 * 24 * 3600 });
    await metricInc(env, "activeUsers", 1);
  } catch (e) {
    console.error("markActive error", e);
  }
}
async function getReportSummary(env, days = 7) {
  days = clamp(safeParseInt(days, 7), 1, 60);
  const out = { days, series: [], totals: {} };
  const totals = {};
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 24 * 3600 * 1000);
    const dayKey = utcDateKey(d);
    const m = (await kvGetJson(env, kMetricDay(dayKey))) || { dayKey, counters: {} };
    const c = m.counters || {};
    out.series.push({ dayKey, ...c });
    for (const [k, v] of Object.entries(c)) totals[k] = (totals[k] || 0) + safeParseInt(v, 0);
  }
  out.totals = totals;
  return out;
}

// ========== Rate limit (best-effort) ==========
async function rateLimitAllow(env, cfg, scope, who, limitPerMin) {
  try {
    const minuteKey = String(Math.floor(nowMs() / 60000));
    const k = kRateLimit(scope, String(who), minuteKey);
    const raw = await env.BOT_KV.get(k);
    const count = safeParseInt(raw, 0) + 1;
    if (count > limitPerMin) return { ok: false, count, limit: limitPerMin };
    await env.BOT_KV.put(k, String(count), { expirationTtl: 90 });
    return { ok: true, count, limit: limitPerMin };
  } catch (e) {
    console.error("rateLimitAllow error", e);
    // Fail-open (never crash)
    return { ok: true, count: 0, limit: limitPerMin };
  }
}

// ========== Dedupe updates ==========
async function isDuplicateUpdate(env, updateId) {
  if (!Number.isFinite(updateId)) return false;
  const key = kDedupeUpdate(updateId);
  try {
    const exists = await env.BOT_KV.get(key);
    if (exists) return true;
    await env.BOT_KV.put(key, "1", { expirationTtl: 60 });
    return false;
  } catch (e) {
    console.error("dedupe error", e);
    return false;
  }
}

// ========== Circuit breaker ==========
async function circuitIsOpen(env, name) {
  const key = kCircuit(name);
  const st = await kvGetJson(env, key);
  const openUntil = Number(st?.openUntil || 0);
  if (openUntil > nowMs()) return true;
  return false;
}
async function circuitReport(env, name, ok) {
  const key = kCircuit(name);
  const st = (await kvGetJson(env, key)) || { fails: 0, openUntil: 0, lastFailAt: 0, lastOkAt: 0 };
  if (ok) {
    st.fails = 0;
    st.openUntil = 0;
    st.lastOkAt = nowMs();
  } else {
    st.fails = safeParseInt(st.fails, 0) + 1;
    st.lastFailAt = nowMs();
    if (st.fails >= 3) {
      st.openUntil = nowMs() + 5 * 60 * 1000; // 5 min open
    }
  }
  await kvPutJson(env, key, st, { expirationTtl: 60 * 60 });
}

// ========== Telegram API ==========
async function tgCall(env, method, payload) {
  const token = toStr(env.BOT_TOKEN).trim();
  if (!token) return null;
  const url = `https://api.telegram.org/bot${token}/${method}`;
  try {
    const res = await fetchWithTimeout(
      url,
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload || {}) },
      12000
    );
    return await safeJson(res);
  } catch (e) {
    console.error("tgCall error", method, e);
    return null;
  }
}
async function tgSendMessage(env, chatId, text, replyMarkup = null, extra = {}) {
  const payload = { chat_id: chatId, text: text || "", disable_web_page_preview: true, ...extra };
  if (replyMarkup) payload.reply_markup = replyMarkup;
  return await tgCall(env, "sendMessage", payload);
}
async function tgEditMessageText(env, chatId, messageId, text, inlineMarkup = null, extra = {}) {
  const payload = { chat_id: chatId, message_id: messageId, text: text || "", disable_web_page_preview: true, ...extra };
  if (inlineMarkup && inlineMarkup.inline_keyboard) payload.reply_markup = inlineMarkup;
  return await tgCall(env, "editMessageText", payload);
}
async function tgSendChatAction(env, chatId, action) {
  return await tgCall(env, "sendChatAction", { chat_id: chatId, action });
}
async function tgSendPhoto(env, chatId, photoUrl, caption = "", extra = {}) {
  const payload = { chat_id: chatId, photo: photoUrl, caption: caption || "", ...extra };
  return await tgCall(env, "sendPhoto", payload);
}
async function tgAnswerCallback(env, callbackQueryId, text = "", showAlert = false) {
  return await tgCall(env, "answerCallbackQuery", { callback_query_id: callbackQueryId, text, show_alert: showAlert });
}

// ========== Keyboards ==========
function mainMenuKeyboard() {
  return {
    keyboard: [
      [{ text: "📈 تحلیل/سیگنال" }, { text: "⚙️ تنظیمات" }],
      [{ text: "👤 پروفایل" }, { text: "💳 خرید اشتراک" }],
      [{ text: "🎁 رفرال" }, { text: "🧠 تعیین سطح" }],
      [{ text: "🆘 پشتیبانی" }, { text: "📚 آموزش" }],
      [{ text: "🧩 Mini App" }]
    ],
    resize_keyboard: true,
    is_persistent: true
  };
}
function backToMenuKeyboard() {
  return { keyboard: [[{ text: "⬅️ منو" }]], resize_keyboard: true, is_persistent: true };
}
function contactKeyboard() {
  return {
    keyboard: [[{ text: "📱 ارسال شماره (Share Contact)", request_contact: true }], [{ text: "⬅️ منو" }]],
    resize_keyboard: true,
    one_time_keyboard: true,
    is_persistent: true
  };
}
function marketsKeyboard() {
  return {
    keyboard: [
      [{ text: "CRYPTO" }, { text: "FOREX" }],
      [{ text: "METALS" }, { text: "STOCKS" }],
      [{ text: "⬅️ منو" }]
    ],
    resize_keyboard: true,
    is_persistent: true
  };
}
function symbolsKeyboard(market) {
  const m = String(market || "").toUpperCase();
  const popular = {
    CRYPTO: ["BTCUSDT", "ETHUSDT", "BNBUSDT", "SOLUSDT", "XRPUSDT"],
    FOREX: ["EURUSD", "GBPUSD", "USDJPY", "AUDUSD", "USDCAD"],
    METALS: ["XAUUSD", "XAGUSD", "WTI", "BRENT"],
    STOCKS: ["AAPL", "TSLA", "NVDA", "MSFT", "AMZN"]
  };
  const arr = popular[m] || [];
  const rows = [];
  for (let i = 0; i < arr.length; i += 2) rows.push([{ text: arr[i] }, ...(arr[i + 1] ? [{ text: arr[i + 1] }] : [])]);
  rows.push([{ text: "🔎 نماد دلخواه (تایپ کن)" }]);
  rows.push([{ text: "⬅️ منو" }]);
  return { keyboard: rows, resize_keyboard: true, is_persistent: true };
}
function settingsKeyboard(cfg, user) {
  const tf = user.settings.tf || "H1";
  const risk = user.settings.risk || "متوسط";
  const news = user.settings.news ? "روشن ✅" : "خاموش ❌";
  const style = user.settings.style || "GENERAL";
  return {
    keyboard: [
      [{ text: `⏱ تایم‌فریم: ${tf}` }, { text: `⚠️ ریسک: ${risk}` }],
      [{ text: `🧠 سبک: ${styleLabel(cfg, style)}` }],
      [{ text: `📰 News: ${news}` }],
      [{ text: "🧩 انتخاب سبک (لیست)" }],
      [{ text: "⬅️ منو" }]
    ],
    resize_keyboard: true,
    is_persistent: true
  };
}
function buyInlineKeyboard() {
  return {
    inline_keyboard: [
      [{ text: "✅ ثبت TXID (/tx)", callback_data: "buy:txid" }],
      [{ text: "💰 نمایش ولت", callback_data: "buy:wallet" }],
      [{ text: "🧾 راهنما", callback_data: "buy:help" }]
    ]
  };
}
function levelResultInline() {
  return {
    inline_keyboard: [
      [{ text: "🔁 درخواست تعیین سطح مجدد", callback_data: "level:req:retry" }],
      [{ text: "⚙️ درخواست تغییر تنظیمات", callback_data: "level:req:settings" }]
    ]
  };
}

// Mapping ReplyKeyboard button text -> command
function mapButtonToCommand(text) {
  const t = String(text || "").trim();
  const m = {
    "📈 تحلیل/سیگنال": "/signals",
    "⚙️ تنظیمات": "/settings",
    "👤 پروفایل": "/profile",
    "💳 خرید اشتراک": "/buy",
    "🎁 رفرال": "/ref",
    "🧠 تعیین سطح": "/level",
    "🆘 پشتیبانی": "/support",
    "📚 آموزش": "/education",
    "🧩 Mini App": "/miniapp",
    "⬅️ منو": "/menu"
  };
  return m[t] || "";
}

// ========== Quota ==========
function computeQuotaView(env, cfg, user, userId) {
  const staff = isAdminId(env, userId);
  if (staff) {
    return {
      plan: user.subscription?.active ? "SUB" : "STAFF",
      dailyLimit: Infinity,
      dailyUsed: 0,
      monthlyLimit: Infinity,
      monthlyUsed: 0
    };
  }
  const isSub = !!user.subscription?.active && user.subscription.until > nowMs();
  const dailyLimit = isSub ? (user.subscription.dailyLimit || cfg.subscription.dailyLimit) : cfg.limits.freeDaily;
  const monthlyLimit = isSub ? null : cfg.limits.freeMonthly;
  return {
    plan: isSub ? "SUB" : "FREE",
    dailyLimit,
    dailyUsed: safeParseInt(user.quota.dayUsed, 0),
    monthlyLimit,
    monthlyUsed: safeParseInt(user.quota.monthUsed, 0)
  };
}
function quotaBar(used, limit) {
  if (!Number.isFinite(limit) || limit <= 0) return "∞";
  const pct = clamp(Math.round((used / limit) * 100), 0, 100);
  const filled = Math.round(pct / 10);
  const bar = "█".repeat(filled) + "░".repeat(10 - filled);
  return `${bar} ${pct}% (${used}/${limit})`;
}
function canConsumeQuota(view) {
  if (!Number.isFinite(view.dailyLimit)) return true;
  if (view.dailyUsed >= view.dailyLimit) return false;
  if (view.monthlyLimit !== null && view.monthlyUsed >= view.monthlyLimit) return false;
  return true;
}
function consumeQuota(user, view) {
  if (!Number.isFinite(view.dailyLimit)) return;
  user.quota.dayUsed = safeParseInt(user.quota.dayUsed, 0) + 1;
  if (view.monthlyLimit !== null) user.quota.monthUsed = safeParseInt(user.quota.monthUsed, 0) + 1;
}

// ========== Referral ==========
async function resolveReferralOwnerId(env, code) {
  const c = String(code || "").trim();
  if (!c) return "";
  const uid = await env.BOT_KV.get(kRefCode(c));
  return uid ? String(uid) : "";
}
async function isPhoneDuplicate(env, phoneNorm, userId) {
  const hash = await sha256Hex(phoneNorm);
  const owner = await env.BOT_KV.get(kPhoneHash(hash));
  return owner && String(owner) !== String(userId);
}
async function bindPhone(env, phoneNorm, userId) {
  const hash = await sha256Hex(phoneNorm);
  await env.BOT_KV.put(kPhoneHash(hash), String(userId), { expirationTtl: 365 * 24 * 3600 });
}
async function tryAwardReferral(env, cfg, inviteeUser, inviteeId) {
  const inviterId = String(inviteeUser.referral?.referredBy || "").trim();
  if (!inviterId) return { ok: false, reason: "no_ref" };

  const phoneNorm = normalizePhone(inviteeUser.profile?.phone || "");
  if (!phoneNorm) return { ok: false, reason: "no_phone" };

  const dup = await isPhoneDuplicate(env, phoneNorm, inviteeId);
  if (dup) {
    inviteeUser.referral.referredBy = "";
    await saveUser(env, inviteeUser);
    return { ok: false, reason: "phone_used" };
  }

  // award inviter
  const inviter = await ensureUser(env, inviterId);
  inviter.referral.invites = safeParseInt(inviter.referral.invites, 0) + 1;
  inviter.referral.successfulInvites = safeParseInt(inviter.referral.successfulInvites, 0) + 1;
  inviter.referral.points = safeParseInt(inviter.referral.points, 0) + cfg.points.perInvite;

  const tier = Math.min(cfg.commission.maxPct, inviter.referral.successfulInvites * cfg.commission.stepPct);
  inviter.referral.commissionPct = tier;

  await saveUser(env, inviter);
  return { ok: true, inviterId };
}

// ========== Payments ==========
function validTxid(txid) {
  const t = String(txid || "").trim();
  return /^[a-fA-F0-9]{12,120}$/.test(t);
}
async function publicWallet(env, cfg) {
  const w = String(cfg.walletPublic || "").trim();
  if (w) return w;
  return String(env.BOT_PUBLIC_WALLET || "").trim();
}
async function registerTx(env, cfg, userId, txid) {
  const t = String(txid || "").trim();
  if (!validTxid(t)) return { ok: false, error: "TXID نامعتبر است. فقط حروف/اعداد هگز." };

  const existing = await kvGetJson(env, kPayment(t));
  if (existing && existing.status && existing.status !== "rejected" && existing.status !== "expired") {
    return { ok: false, error: "این TXID قبلاً ثبت شده است." };
  }

  const createdAt = nowMs();
  const record = {
    txid: t,
    userId: String(userId),
    status: "pending",
    createdAt,
    updatedAt: createdAt,
    priceUSDT: cfg.subscription.priceUSDT,
    durationDays: cfg.subscription.durationDays,
    subDailyLimit: cfg.subscription.dailyLimit,
    note: ""
  };

  await kvPutJson(env, kPayment(t), record);
  await kvPutText(env, kPayIdx("pending", createdAt, t), "1", { expirationTtl: 60 * 24 * 3600 });

  await metricInc(env, "paymentsPending", 1);

  return { ok: true, record };
}
async function listPaymentsByStatus(env, status, limit = 50, cursor = "") {
  const prefix = `${KV_PREFIX}pidx:${status}:`;
  const r = await kvList(env, prefix, limit, cursor || undefined);
  const txids = r.keys.map((k) => k.name.split(":").pop()).filter(Boolean);
  const items = [];
  for (const txid of txids) {
    const p = await kvGetJson(env, kPayment(txid));
    if (p) items.push(p);
  }
  items.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  return { items, cursor: r.cursor || "" };
}
async function approvePayment(env, cfg, txid, approverId) {
  const t = String(txid || "").trim();
  const p = await kvGetJson(env, kPayment(t));
  if (!p || p.status !== "pending") return { ok: false, error: "TXID پیدا نشد یا pending نیست." };

  p.status = "approved";
  p.updatedAt = nowMs();
  p.approvedBy = String(approverId);
  p.approvedAt = p.updatedAt;

  await kvPutJson(env, kPayment(t), p);
  await kvPutText(env, kPayIdx("approved", p.approvedAt, t), "1", { expirationTtl: 120 * 24 * 3600 });
  await kvDel(env, kPayIdx("pending", p.createdAt, t));

  // Activate subscription
  const u = await ensureUser(env, p.userId);
  const days = Math.max(1, safeParseInt(p.durationDays, cfg.subscription.durationDays));
  const addMs = days * 24 * 3600 * 1000;
  const base = u.subscription?.active && u.subscription.until > nowMs() ? u.subscription.until : nowMs();
  u.subscription.active = true;
  u.subscription.until = base + addMs;
  u.subscription.plan = "SUB";
  u.subscription.dailyLimit = Math.max(1, safeParseInt(p.subDailyLimit, cfg.subscription.dailyLimit));
  await saveUser(env, u);

  await metricInc(env, "paymentsApproved", 1);

  // Commission points for inviter (tiered) – bonus points on successful purchase
  if (u.referral?.referredBy) {
    const inv = await ensureUser(env, u.referral.referredBy);
    const pct = clamp(safeParseInt(inv.referral?.commissionPct || 0, 0), 0, 50);
    const bonus = Math.round((pct / 100) * cfg.points.buySub);
    if (bonus > 0) {
      inv.referral.points = safeParseInt(inv.referral.points, 0) + bonus;
      await saveUser(env, inv);
    }
  }

  return { ok: true, payment: p, user: u };
}
async function rejectPayment(env, txid, approverId, reason = "") {
  const t = String(txid || "").trim();
  const p = await kvGetJson(env, kPayment(t));
  if (!p || p.status !== "pending") return { ok: false, error: "TXID پیدا نشد یا pending نیست." };

  p.status = "rejected";
  p.updatedAt = nowMs();
  p.rejectedBy = String(approverId);
  p.rejectedAt = p.updatedAt;
  p.note = String(reason || "").slice(0, 500);

  await kvPutJson(env, kPayment(t), p);
  await kvPutText(env, kPayIdx("rejected", p.rejectedAt, t), "1", { expirationTtl: 120 * 24 * 3600 });
  await kvDel(env, kPayIdx("pending", p.createdAt, t));

  await metricInc(env, "paymentsRejected", 1);

  return { ok: true, payment: p };
}
async function expireOldPendingPayments(env, cfg) {
  // Expire pending older than 24h (housekeeping)
  const cutoff = nowMs() - 24 * 3600 * 1000;
  const { items } = await listPaymentsByStatus(env, "pending", 80, "");
  for (const p of items) {
    if ((p.createdAt || 0) < cutoff) {
      p.status = "expired";
      p.updatedAt = nowMs();
      await kvPutJson(env, kPayment(p.txid), p);
      await kvPutText(env, kPayIdx("expired", p.updatedAt, p.txid), "1", { expirationTtl: 120 * 24 * 3600 });
      await kvDel(env, kPayIdx("pending", p.createdAt, p.txid));
      // Notify user
      await tgSendMessage(env, p.userId, `⏳ پرداخت شما منقضی شد.\nTXID: ${p.txid}\nاگر پرداخت انجام شده، لطفاً دوباره /tx را ارسال کن یا با پشتیبانی تماس بگیر.`, mainMenuKeyboard());
      await metricInc(env, "paymentsExpired", 1);
    }
  }
}

// ========== Tickets ==========
async function createTicket(env, fromUserId, messageText) {
  const id = `${nowMs()}-${randomToken(6)}`;
  const ts = nowMs();
  const ticket = {
    id,
    status: "open",
    createdAt: ts,
    updatedAt: ts,
    fromUserId: String(fromUserId),
    messages: [{ from: "user", at: ts, text: String(messageText || "").slice(0, 4000) }],
    reply: ""
  };
  await kvPutJson(env, kTicket(id), ticket, { expirationTtl: 365 * 24 * 3600 });
  await kvPutText(env, kTicketIdx("open", ts, id), "1", { expirationTtl: 365 * 24 * 3600 });
  await metricInc(env, "ticketsNew", 1);
  return ticket;
}
async function listTickets(env, status = "open", limit = 50, cursor = "") {
  const prefix = `${KV_PREFIX}tidx:${status}:`;
  const r = await kvList(env, prefix, limit, cursor || undefined);
  const ids = r.keys.map((k) => k.name.split(":").pop()).filter(Boolean);
  const out = [];
  for (const id of ids) {
    const t = await kvGetJson(env, kTicket(id));
    if (t) out.push(t);
  }
  out.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  return { items: out, cursor: r.cursor || "" };
}
async function replyTicket(env, ticketId, replyText, replierId) {
  const id = String(ticketId || "").trim();
  const t = await kvGetJson(env, kTicket(id));
  if (!t) return { ok: false, error: "تیکت پیدا نشد." };

  t.status = "answered";
  t.updatedAt = nowMs();
  t.reply = String(replyText || "").slice(0, 4000);
  t.messages = t.messages || [];
  t.messages.push({ from: "staff", at: t.updatedAt, by: String(replierId), text: t.reply });

  await kvPutJson(env, kTicket(id), t, { expirationTtl: 365 * 24 * 3600 });
  await kvPutText(env, kTicketIdx("answered", t.updatedAt, id), "1", { expirationTtl: 365 * 24 * 3600 });
  // remove open index if exists (best-effort)
  await kvDel(env, kTicketIdx("open", t.createdAt, id));

  await metricInc(env, "ticketsAnswered", 1);

  return { ok: true, ticket: t };
}
async function ticketSlaReminder(env) {
  // Remind staff if open tickets older than 6 hours
  const cutoff = nowMs() - 6 * 3600 * 1000;
  const { items } = await listTickets(env, "open", 50, "");
  for (const t of items) {
    if ((t.createdAt || 0) < cutoff && !(t._reminded)) {
      // set reminder flag (store)
      t._reminded = true;
      t.updatedAt = nowMs();
      await kvPutJson(env, kTicket(t.id), t, { expirationTtl: 365 * 24 * 3600 });
      await notifyStaff(env, `⏰ یادآوری: تیکت باز بیش از 6 ساعت\nTicket: ${t.id}\nUser: ${t.fromUserId}\nمتن: ${trunc(t.messages?.[0]?.text || "", 600)}`);
    }
  }
}

// ========== Requests (deposit/withdraw) ==========
async function createRequest(env, userId, kind, payload) {
  const id = `${nowMs()}-${randomToken(6)}`;
  const ts = nowMs();
  const req = { id, status: "open", createdAt: ts, updatedAt: ts, userId: String(userId), kind: String(kind || ""), payload: payload || {} };
  await kvPutJson(env, kRequest(id), req, { expirationTtl: 365 * 24 * 3600 });
  await kvPutText(env, kRequestIdx("open", ts, id), "1", { expirationTtl: 365 * 24 * 3600 });
  await metricInc(env, "requestsNew", 1);
  return req;
}
async function listRequests(env, status = "open", limit = 50, cursor = "") {
  const prefix = `${KV_PREFIX}ridx:${status}:`;
  const r = await kvList(env, prefix, limit, cursor || undefined);
  const ids = r.keys.map((k) => k.name.split(":").pop()).filter(Boolean);
  const out = [];
  for (const id of ids) {
    const rr = await kvGetJson(env, kRequest(id));
    if (rr) out.push(rr);
  }
  out.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  return { items: out, cursor: r.cursor || "" };
}
async function markRequestDone(env, reqId, staffId, note = "") {
  const id = String(reqId || "").trim();
  const rr = await kvGetJson(env, kRequest(id));
  if (!rr) return { ok: false, error: "درخواست پیدا نشد." };
  rr.status = "done";
  rr.updatedAt = nowMs();
  rr.doneBy = String(staffId);
  rr.note = String(note || "").slice(0, 500);

  await kvPutJson(env, kRequest(id), rr, { expirationTtl: 365 * 24 * 3600 });
  await kvPutText(env, kRequestIdx("done", rr.updatedAt, id), "1", { expirationTtl: 365 * 24 * 3600 });
  await kvDel(env, kRequestIdx("open", rr.createdAt, id));

  await metricInc(env, "requestsDone", 1);
  return { ok: true, req: rr };
}

// ========== Staff notify ==========
async function notifyStaff(env, text, inlineKeyboard = null) {
  const staff = new Set([...parseIdSet(env.OWNER_IDS), ...parseIdSet(env.ADMIN_IDS)]);
  for (const id of staff) {
    await tgSendMessage(env, id, text, mainMenuKeyboard(), inlineKeyboard ? { reply_markup: inlineKeyboard } : {});
  }
}
async function notifyOwners(env, text) {
  const owners = parseIdSet(env.OWNER_IDS);
  for (const id of owners) {
    await tgSendMessage(env, id, text, mainMenuKeyboard());
  }
}

// ========== News ==========
function stripCdata(s) {
  return String(s || "").replace(/<!\[CDATA\[|\]\]>/g, "");
}
function decodeXmlEntities(s) {
  return String(s || "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}
function parseRssItems(xmlText) {
  const xml = String(xmlText || "");
  const items = [];
  const itemRegex = /<item\b[^>]*>([\s\S]*?)<\/item>/gi;
  let m;
  while ((m = itemRegex.exec(xml))) {
    const block = m[1];
    const getTag = (tag) => {
      const re = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, "i");
      const mm = re.exec(block);
      return mm ? decodeXmlEntities(stripCdata(mm[1]).trim()) : "";
    };
    const title = getTag("title");
    const link = getTag("link");
    const pubDate = getTag("pubDate") || getTag("published") || getTag("dc:date");
    const desc = getTag("description");
    if (title) items.push({ title, link, pubDate, desc });
  }
  return items;
}
function isNoisyTitle(cfg, title) {
  const t = String(title || "").toLowerCase();
  const bad = cfg?.news?.noiseFilters || [];
  return bad.some((b) => t.includes(String(b).toLowerCase()));
}
function scoreNewsItem(item, symbol, market) {
  const title = String(item.title || "");
  const desc = String(item.desc || "");
  const text = (title + " " + desc).toLowerCase();
  const sym = String(symbol || "").toLowerCase();

  let relevance = 0;
  if (sym && text.includes(sym)) relevance += 5;

  const m = String(market || "").toUpperCase();
  const keywords = [];
  if (m === "CRYPTO") keywords.push("bitcoin", "btc", "ethereum", "eth", "binance", "sec", "etf", "hack", "stablecoin");
  if (m === "FOREX") keywords.push("fed", "cpi", "inflation", "rates", "ecb", "boj", "nfp", "gdp", "pmi", "fomc");
  if (m === "STOCKS") keywords.push("earnings", "guidance", "dow", "nasdaq", "s&p", "inflation", "sec", "buyback");
  if (m === "METALS") keywords.push("gold", "xau", "silver", "xag", "oil", "wti", "brent", "yields", "dollar");

  for (const k of keywords) if (text.includes(k)) relevance += 1;

  let impact = 0;
  const impactWords = ["break", "surge", "plunge", "crash", "lawsuit", "ban", "approval", "rate hike", "rate cut", "inflation", "sanction"];
  for (const w of impactWords) if (text.includes(w)) impact += 1;

  let recency = 0;
  const ts = Date.parse(item.pubDate || "");
  if (Number.isFinite(ts)) {
    const ageMin = (nowMs() - ts) / 60000;
    recency = clamp(Math.round(10 - ageMin / 60), 0, 10);
  } else {
    recency = 2;
  }

  return relevance * 3 + impact * 2 + recency;
}
async function fetchEconomicCalendarEvents(cfg, symbol) {
  const out = [];
  const sym = String(symbol || "").toUpperCase().replace(/[^A-Z]/g, "");
  if (!/^[A-Z]{6}$/.test(sym)) return out;

  const c1 = sym.slice(0, 3);
  const c2 = sym.slice(3, 6);
  const sources = cfg?.news?.forexCalendar?.sources || [];
  for (const url of sources) {
    try {
      const res = await fetchWithTimeout(url, { method: "GET" }, 9000);
      if (!res.ok) continue;
      const j = await safeJson(res);
      const arr = Array.isArray(j) ? j : (Array.isArray(j?.events) ? j.events : []);
      for (const ev of arr) {
        const cur = String(ev.currency || ev.cur || "").toUpperCase().trim();
        if (!cur || (cur !== c1 && cur !== c2)) continue;

        const imp = String(ev.impact || ev.impactTitle || "").toLowerCase();
        const isHigh = imp.includes("high") || imp.includes("red");
        const isMed = imp.includes("medium") || imp.includes("orange") || imp.includes("yellow");
        if (!isHigh && !isMed) continue;

        const title = String(ev.title || ev.event || ev.name || "").trim();
        if (!title) continue;

        const ts =
          Number(ev.timestamp) > 0 ? Number(ev.timestamp) * (Number(ev.timestamp) < 2e12 ? 1000 : 1) :
          (Number.isFinite(Date.parse(ev.date || "")) ? Date.parse(ev.date) : nowMs());

        out.push({
          title: `[Calendar ${cur}] ${title} (${isHigh ? "High" : "Medium"})`,
          link: String(ev.url || ev.link || "").trim() || "https://www.forexfactory.com/calendar",
          pubDate: new Date(ts).toUTCString(),
          desc: String(ev.forecast || "") ? `Forecast: ${ev.forecast} / Prev: ${ev.previous || ""}` : ""
        });
      }
      if (out.length) break;
    } catch (e) {
      console.error("calendar error", e);
    }
  }
  return out;
}
function deterministicNewsSummaryPersian(items) {
  if (!items.length) return "خبر مهمی پیدا نشد یا منابع در دسترس نبودند.";
  const lines = [];
  for (let i = 0; i < Math.min(6, items.length); i++) {
    const it = items[i];
    const title = String(it.title || "").trim();
    const link = String(it.link || "").trim();
    lines.push(`${i + 1}) ${title}${link ? `\n${link}` : ""}`);
  }
  return lines.join("\n\n");
}

// AI-based news summarization (strict JSON if possible)
async function aiNewsSummary(env, cfg, items, market, symbol) {
  const list = items.slice(0, 10).map((it) => ({ title: it.title, link: it.link, pubDate: it.pubDate, score: it.score }));
  const prompt =
    "تو یک تحلیل‌گر خبر بازار هستی. خروجی را فقط JSON معتبر بده.\n" +
    "هدف: خلاصه فارسی کوتاه + رتبه‌بندی دقیق بر اساس relevance/impact/recency.\n" +
    "Noise حذف شود (weekly recap, sponsored, wrap, top ...).\n" +
    `Market=${market}, Symbol=${symbol}\n` +
    "Schema:\n" +
    "{\"summary_fa\":string,\"ranked\":[{\"title\":string,\"link\":string,\"relevance\":number,\"impact\":number,\"recency\":number,\"note\":string}]}\n" +
    "Items:\n" + JSON.stringify(list);

  const r = await callAI(env, cfg, "news", [{ role: "user", content: prompt }], 12000);
  if (!r.ok) return { ok: false, error: r.error };

  const obj = extractLastJsonObject(r.text) || tryParseJson(r.text);
  if (!obj || typeof obj !== "object" || !Array.isArray(obj.ranked)) return { ok: false, error: "bad_json" };

  const ranked = obj.ranked.slice(0, 8).map((x) => ({
    title: String(x.title || "").slice(0, 180),
    link: String(x.link || "").slice(0, 500),
    relevance: clamp(Number(x.relevance || 0), 0, 10),
    impact: clamp(Number(x.impact || 0), 0, 10),
    recency: clamp(Number(x.recency || 0), 0, 10),
    note: String(x.note || "").slice(0, 120)
  }));

  return { ok: true, summary_fa: String(obj.summary_fa || "").slice(0, 1500), ranked };
}

async function getNewsBundle(env, cfg, market, symbol) {
  const tag = `${String(market || "").toUpperCase()}:${String(symbol || "").toUpperCase()}`;
  const cacheKey = kNewsCache(tag);
  const ttl = cfg.news.ttlMs || 600000;

  const cached = await kvGetJson(env, cacheKey);
  if (cached && cached.ts && nowMs() - cached.ts < ttl && Array.isArray(cached.items)) return cached;

  const items = [];

  // Forex calendar
  if (String(market || "").toUpperCase() === "FOREX" && cfg.news.forexCalendar?.enabled) {
    const cal = await fetchEconomicCalendarEvents(cfg, symbol);
    items.push(...cal);
  }

  const rssUrls = cfg.news.rss || [];
  for (const u of rssUrls) {
    if (await circuitIsOpen(env, `rss:${u}`)) continue;
    try {
      const res = await fetchWithTimeout(u, { method: "GET" }, 9000);
      if (!res.ok) throw new Error("rss_bad");
      const xml = await safeText(res);
      const parsed = parseRssItems(xml).filter((it) => it.title && !isNoisyTitle(cfg, it.title));
      items.push(...parsed);
      await circuitReport(env, `rss:${u}`, true);
    } catch (e) {
      console.error("rss fetch err", u, e);
      await circuitReport(env, `rss:${u}`, false);
    }
  }

  // Dedup
  const seen = new Set();
  const dedup = [];
  for (const it of items) {
    const key = (it.link || it.title || "").slice(0, 240);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    dedup.push(it);
  }

  // Score
  const scored = dedup
    .map((it) => ({ ...it, score: scoreNewsItem(it, symbol, market) }))
    .sort((a, b) => (b.score || 0) - (a.score || 0))
    .slice(0, 12);

  // AI summarization if possible
  let ai = null;
  if (scored.length) {
    try {
      ai = await aiNewsSummary(env, cfg, scored, market, symbol);
    } catch {
      ai = null;
    }
  }

  const bundle = {
    ts: nowMs(),
    tag,
    items: scored,
    summary_fa: ai?.ok ? ai.summary_fa : deterministicNewsSummaryPersian(scored),
    ranked: ai?.ok ? ai.ranked : []
  };

  await kvPutJson(env, cacheKey, bundle, { expirationTtl: Math.ceil(ttl / 1000) });
  return bundle;
}

// ========== AI Providers ==========
function tryParseJson(text) {
  try {
    return JSON.parse(String(text || ""));
  } catch {
    return null;
  }
}
function extractLastJsonObject(text) {
  const s = String(text || "");
  const last = s.lastIndexOf("{");
  if (last < 0) return null;
  const cand = s.slice(last);
  const first = cand.indexOf("{");
  const lastBrace = cand.lastIndexOf("}");
  if (first < 0 || lastBrace < 0) return null;
  const snippet = cand.slice(first, lastBrace + 1);
  try {
    return JSON.parse(snippet);
  } catch {
    return null;
  }
}
async function callAI(env, cfg, purpose, messages, timeoutMs = 15000) {
  const provider = String(env.AI_PROVIDER || "cloudflare").toLowerCase();

  // Circuit breaker per provider
  const cbName = `ai:${provider}:${purpose}`;
  if (await circuitIsOpen(env, cbName)) return { ok: false, error: "ai_circuit_open" };

  // Cloudflare AI binding
  if (provider === "cloudflare") {
    if (!env.AI || !env.AI.run) return { ok: false, error: "Cloudflare AI binding not available" };
    try {
      const model = "@cf/meta/llama-3.1-8b-instruct";
      const prompt = messages.map((m) => `${m.role.toUpperCase()}: ${m.content}`).join("\n\n");
      const p = env.AI.run(model, { prompt, max_tokens: 1400 });
      const out = await promiseWithTimeout(p, timeoutMs, "ai_timeout");
      const text = out?.response || out?.output_text || JSON.stringify(out);
      await circuitReport(env, cbName, true);
      return { ok: true, text: String(text || "") };
    } catch (e) {
      console.error("CF AI error", e);
      await circuitReport(env, cbName, false);
      return { ok: false, error: String(e?.message || e) };
    }
  }

  // OpenAI
  if (provider === "openai") {
    const key = String(env.OPENAI_API_KEY || "").trim();
    const model = String(env.OPENAI_MODEL || "gpt-4o-mini").trim();
    if (!key) return { ok: false, error: "OPENAI_API_KEY missing" };
    try {
      const res = await fetchWithTimeout(
        "https://api.openai.com/v1/chat/completions",
        {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
          body: JSON.stringify({ model, messages, temperature: 0.3 })
        },
        timeoutMs
      );
      const j = await safeJson(res);
      const text = j?.choices?.[0]?.message?.content || "";
      await circuitReport(env, cbName, true);
      return { ok: true, text: String(text || "") };
    } catch (e) {
      console.error("OpenAI error", e);
      await circuitReport(env, cbName, false);
      return { ok: false, error: String(e?.message || e) };
    }
  }

  // Gemini
  if (provider === "gemini") {
    const key = String(env.GEMINI_API_KEY || "").trim();
    const model = String(env.GEMINI_MODEL || "gemini-1.5-flash").trim();
    if (!key) return { ok: false, error: "GEMINI_API_KEY missing" };
    try {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(key)}`;
      const contents = messages.map((m) => ({ role: m.role === "assistant" ? "model" : "user", parts: [{ text: m.content }] }));
      const res = await fetchWithTimeout(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ contents }) }, timeoutMs);
      const j = await safeJson(res);
      const text = j?.candidates?.[0]?.content?.parts?.map((p) => p.text).join("\n") || "";
      await circuitReport(env, cbName, true);
      return { ok: true, text: String(text || "") };
    } catch (e) {
      console.error("Gemini error", e);
      await circuitReport(env, cbName, false);
      return { ok: false, error: String(e?.message || e) };
    }
  }

  // Compat (OpenAI-compatible)
  if (provider === "compat") {
    const base = String(env.AI_COMPAT_BASE_URL || "").trim();
    const key = String(env.AI_COMPAT_API_KEY || "").trim();
    const model = String(env.AI_COMPAT_MODEL || "").trim();
    if (!base || !key || !model) return { ok: false, error: "AI_COMPAT_* missing" };
    try {
      const url = base.replace(/\/+$/, "") + "/chat/completions";
      const res = await fetchWithTimeout(
        url,
        {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
          body: JSON.stringify({ model, messages, temperature: 0.3 })
        },
        timeoutMs
      );
      const j = await safeJson(res);
      const text = j?.choices?.[0]?.message?.content || "";
      await circuitReport(env, cbName, true);
      return { ok: true, text: String(text || "") };
    } catch (e) {
      console.error("Compat error", e);
      await circuitReport(env, cbName, false);
      return { ok: false, error: String(e?.message || e) };
    }
  }

  return { ok: false, error: "Unknown AI_PROVIDER" };
}

// ========== Zones schema ==========
const ZONES_SCHEMA_HINT =
  "\n\nدر انتهای پاسخ، دقیقاً یک JSON معتبر قرار بده (فقط JSON، بدون متن اضافی). " +
  "Schema: {\"schema\":\"zones_v1\",\"zones\":[{\"kind\":\"demand|supply\",\"price_from\":number,\"price_to\":number,\"note\":string}]} " +
  "حداکثر 8 زون. اگر زونی نیست، zones را خالی بده.\n";

function validateZones(obj) {
  if (!obj || typeof obj !== "object") return { ok: false, zones: [], error: "no_obj" };
  if (obj.schema !== "zones_v1") return { ok: false, zones: [], error: "bad_schema" };
  const zones = Array.isArray(obj.zones) ? obj.zones : [];
  const out = [];
  for (const z of zones.slice(0, 8)) {
    if (!z || typeof z !== "object") continue;
    const kind = String(z.kind || "").toLowerCase();
    if (kind !== "demand" && kind !== "supply") continue;
    let pf = Number(z.price_from);
    let pt = Number(z.price_to);
    if (!Number.isFinite(pf) || !Number.isFinite(pt)) continue;
    pf = Math.abs(pf);
    pt = Math.abs(pt);
    if (pf > pt) [pf, pt] = [pt, pf];
    out.push({ kind, price_from: pf, price_to: pt, note: String(z.note || "").slice(0, 120) });
  }
  return { ok: true, zones: out, error: "" };
}

async function repairZonesJsonOnce(env, cfg, rawText) {
  const prompt =
    "تو یک تعمیرکار JSON هستی. فقط یک JSON معتبر برگردان.\n" +
    "ورودی زیر ممکن است JSON خراب یا همراه متن باشد. فقط JSON نهایی را بده.\n" +
    ZONES_SCHEMA_HINT +
    "\n---INPUT---\n" +
    String(rawText || "").slice(0, 7000);

  const r = await callAI(env, cfg, "repair_zones", [{ role: "user", content: prompt }], 12000);
  if (!r.ok) return null;
  return extractLastJsonObject(r.text) || tryParseJson(r.text);
}

// ========== Market data providers (fallback chain) ==========
function mapTfToBinance(tf) {
  const m = { M15: "15m", M30: "30m", H1: "1h", H4: "4h", D1: "1d" };
  return m[String(tf || "H1").toUpperCase()] || "1h";
}
function mapTfToYahoo(tf) {
  tf = String(tf || "H1").toUpperCase();
  if (tf === "D1") return { range: "6mo", interval: "1d" };
  if (tf === "H4") return { range: "1mo", interval: "1h" };
  if (tf === "M15") return { range: "5d", interval: "15m" };
  if (tf === "M30") return { range: "10d", interval: "30m" };
  return { range: "10d", interval: "1h" };
}
function yahooSymbol(market, symbol) {
  const m = String(market || "").toUpperCase();
  const s = String(symbol || "").toUpperCase();

  // common mappings
  if (s === "WTI") return "CL=F";
  if (s === "BRENT") return "BZ=F";

  if (m === "FOREX") {
    // Yahoo uses EURUSD=X
    if (/^[A-Z]{6}$/.test(s)) return `${s}=X`;
  }
  if (m === "METALS") {
    // Many metals are quoted similarly (XAUUSD=X)
    if (/^XAUUSD$/.test(s) || /^XAGUSD$/.test(s)) return `${s}=X`;
  }
  return s;
}
async function fetchCandlesBinance(symbol, interval, limit) {
  const sym = symbol.toUpperCase();
  const url = `https://api.binance.com/api/v3/klines?symbol=${encodeURIComponent(sym)}&interval=${encodeURIComponent(interval)}&limit=${limit}`;
  const res = await fetchWithTimeout(url, { method: "GET" }, 8000);
  if (!res.ok) throw new Error("binance_bad");
  const arr = await safeJson(res);
  if (!Array.isArray(arr)) throw new Error("binance_parse");
  return arr
    .map((k) => ({ t: Number(k[0]), o: Number(k[1]), h: Number(k[2]), l: Number(k[3]), c: Number(k[4]) }))
    .filter((x) => Number.isFinite(x.t));
}
async function fetchCandlesYahoo(symbol, range = "10d", interval = "1h") {
  const url = `https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(symbol)}?range=${encodeURIComponent(range)}&interval=${encodeURIComponent(interval)}`;
  const res = await fetchWithTimeout(url, { method: "GET" }, 8000);
  if (!res.ok) throw new Error("yahoo_bad");
  const j = await safeJson(res);
  const r = j?.chart?.result?.[0];
  if (!r) throw new Error("yahoo_parse");
  const ts = r.timestamp || [];
  const q = r.indicators?.quote?.[0] || {};
  const out = [];
  for (let i = 0; i < ts.length; i++) {
    const t = Number(ts[i]) * 1000;
    const o = Number(q.open?.[i]);
    const h = Number(q.high?.[i]);
    const l = Number(q.low?.[i]);
    const c = Number(q.close?.[i]);
    if ([t, o, h, l, c].every(Number.isFinite)) out.push({ t, o, h, l, c });
  }
  if (!out.length) throw new Error("yahoo_empty");
  return out;
}
async function fetchCandlesTwelveData(env, symbol, interval, outputsize) {
  const key = String(env.TWELVEDATA_API_KEY || "").trim();
  if (!key) throw new Error("no_twelvedata_key");
  const url = `https://api.twelvedata.com/time_series?symbol=${encodeURIComponent(symbol)}&interval=${encodeURIComponent(interval)}&outputsize=${outputsize}&apikey=${encodeURIComponent(key)}`;
  const res = await fetchWithTimeout(url, { method: "GET" }, 8000);
  if (!res.ok) throw new Error("twelvedata_bad");
  const j = await safeJson(res);
  const values = j?.values;
  if (!Array.isArray(values)) throw new Error("twelvedata_parse");
  const out = values
    .map((v) => {
      const t = Date.parse(v.datetime || v.datetime_utc || "");
      return { t, o: Number(v.open), h: Number(v.high), l: Number(v.low), c: Number(v.close) };
    })
    .filter((x) => [x.t, x.o, x.h, x.l, x.c].every(Number.isFinite));
  out.reverse();
  if (!out.length) throw new Error("twelvedata_empty");
  return out;
}
async function fetchCandlesFinnhub(env, symbol, resolution, fromSec, toSec) {
  const key = String(env.FINNHUB_API_KEY || "").trim();
  if (!key) throw new Error("no_finnhub_key");
  const url = `https://finnhub.io/api/v1/stock/candle?symbol=${encodeURIComponent(symbol)}&resolution=${encodeURIComponent(resolution)}&from=${fromSec}&to=${toSec}&token=${encodeURIComponent(key)}`;
  const res = await fetchWithTimeout(url, { method: "GET" }, 8000);
  if (!res.ok) throw new Error("finnhub_bad");
  const j = await safeJson(res);
  if (j?.s !== "ok") throw new Error("finnhub_notok");
  const out = [];
  for (let i = 0; i < (j.t || []).length; i++) {
    const t = Number(j.t[i]) * 1000;
    const o = Number(j.o[i]), h = Number(j.h[i]), l = Number(j.l[i]), c = Number(j.c[i]);
    if ([t, o, h, l, c].every(Number.isFinite)) out.push({ t, o, h, l, c });
  }
  if (!out.length) throw new Error("finnhub_empty");
  return out;
}
async function fetchCandlesAlphaVantage(env, symbol, interval) {
  const key = String(env.ALPHAVANTAGE_API_KEY || "").trim();
  if (!key) throw new Error("no_av_key");
  const url = `https://www.alphavantage.co/query?function=TIME_SERIES_INTRADAY&symbol=${encodeURIComponent(symbol)}&interval=${encodeURIComponent(interval)}&apikey=${encodeURIComponent(key)}&outputsize=compact`;
  const res = await fetchWithTimeout(url, { method: "GET" }, 8000);
  if (!res.ok) throw new Error("av_bad");
  const j = await safeJson(res);
  const seriesKey = Object.keys(j || {}).find((k) => k.toLowerCase().includes("time series"));
  const series = seriesKey ? j[seriesKey] : null;
  if (!series) throw new Error("av_parse");
  const out = [];
  for (const [dt, v] of Object.entries(series)) {
    const t = Date.parse(dt);
    const o = Number(v["1. open"]), h = Number(v["2. high"]), l = Number(v["3. low"]), c = Number(v["4. close"]);
    if ([t, o, h, l, c].every(Number.isFinite)) out.push({ t, o, h, l, c });
  }
  out.sort((a, b) => a.t - b.t);
  if (!out.length) throw new Error("av_empty");
  return out;
}
async function fetchCandlesPolygon(env, symbol, fromDate, toDate) {
  const key = String(env.POLYGON_API_KEY || "").trim();
  if (!key) throw new Error("no_polygon_key");
  const url = `https://api.polygon.io/v2/aggs/ticker/${encodeURIComponent(symbol)}/range/1/hour/${encodeURIComponent(fromDate)}/${encodeURIComponent(toDate)}?adjusted=true&sort=asc&limit=50000&apiKey=${encodeURIComponent(key)}`;
  const res = await fetchWithTimeout(url, { method: "GET" }, 8000);
  if (!res.ok) throw new Error("polygon_bad");
  const j = await safeJson(res);
  const arr = j?.results || [];
  if (!Array.isArray(arr)) throw new Error("polygon_parse");
  const out = arr
    .map((r) => ({ t: Number(r.t), o: Number(r.o), h: Number(r.h), l: Number(r.l), c: Number(r.c) }))
    .filter((x) => [x.t, x.o, x.h, x.l, x.c].every(Number.isFinite));
  if (!out.length) throw new Error("polygon_empty");
  return out;
}
function snapshotFromCandles(candles) {
  const last = candles[candles.length - 1];
  const prev = candles[candles.length - 2] || last;
  const change = prev && prev.c ? ((last.c - prev.c) / prev.c) * 100 : 0;
  let hi = -Infinity, lo = Infinity;
  for (const c of candles.slice(-80)) {
    hi = Math.max(hi, c.h);
    lo = Math.min(lo, c.l);
  }
  return { lastClose: last.c, changePct: change, rangeHi: hi, rangeLo: lo };
}
async function getCandlesWithFallback(env, cfg, market, symbol, tf) {
  const tfU = String(tf || "H1").toUpperCase();
  const limit = tfU === "D1" ? 180 : 260;

  const tasks = [];

  // Binance first for CRYPTO
  if (String(market || "").toUpperCase() === "CRYPTO") {
    const interval = mapTfToBinance(tfU);
    tasks.push({ name: "binance", fn: async () => fetchCandlesBinance(symbol, interval, limit) });
  }

  // Yahoo
  {
    const { range, interval } = mapTfToYahoo(tfU);
    const ys = yahooSymbol(market, symbol);
    tasks.push({ name: "yahoo", fn: async () => fetchCandlesYahoo(ys, range, interval) });
  }

  // TwelveData
  {
    const interval = tfU === "D1" ? "1day" : (tfU === "M15" ? "15min" : tfU === "M30" ? "30min" : "1h");
    tasks.push({ name: "twelvedata", fn: async () => fetchCandlesTwelveData(env, symbol, interval, limit) });
  }

  // Finnhub
  {
    const resolution = tfU === "D1" ? "D" : "60";
    const to = Math.floor(nowMs() / 1000);
    const from = to - 60 * 60 * 24 * 30;
    tasks.push({ name: "finnhub", fn: async () => fetchCandlesFinnhub(env, symbol, resolution, from, to) });
  }

  // AlphaVantage
  {
    const interval = tfU === "M15" ? "15min" : tfU === "M30" ? "30min" : "60min";
    tasks.push({ name: "alphavantage", fn: async () => fetchCandlesAlphaVantage(env, symbol, interval) });
  }

  // Polygon
  {
    const d = new Date();
    const toDate = utcDateKey(d);
    const fromDate = utcDateKey(new Date(d.getTime() - 20 * 24 * 3600 * 1000));
    tasks.push({ name: "polygon", fn: async () => fetchCandlesPolygon(env, symbol, fromDate, toDate) });
  }

  let lastErr = "";
  for (const t of tasks) {
    const cb = `data:${t.name}:${market}`;
    if (await circuitIsOpen(env, cb)) continue;
    try {
      const candles = await t.fn();
      if (candles && candles.length >= 20) {
        await circuitReport(env, cb, true);
        return candles;
      }
      lastErr = "not_enough_candles";
      await circuitReport(env, cb, false);
    } catch (e) {
      lastErr = String(e?.message || e);
      await circuitReport(env, cb, false);
      continue;
    }
  }
  throw new Error(lastErr || "data_unavailable");
}

// ========== Chart generation (QuickChart) ==========
function buildChartUrl(cfg, symbol, tf, candles, zones) {
  const max = Math.min(140, candles.length);
  const slice = candles.slice(Math.max(0, candles.length - max));
  const labels = slice.map((c) => new Date(c.t).toISOString().slice(5, 16).replace("T", " "));
  const data = slice.map((c) => c.c);

  const annotations = [];
  for (const z of zones || []) {
    annotations.push({
      type: "box",
      xScaleID: "x",
      yScaleID: "y",
      yMin: z.price_from,
      yMax: z.price_to,
      backgroundColor: z.kind === "demand" ? "rgba(0,200,0,0.15)" : "rgba(200,0,0,0.15)",
      borderColor: z.kind === "demand" ? "rgba(0,140,0,0.7)" : "rgba(140,0,0,0.7)",
      borderWidth: 1
    });
  }

  const qc = {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: `${symbol} (${tf}) Close`,
          data,
          fill: false,
          borderWidth: 2,
          pointRadius: 0,
          tension: 0.15
        }
      ]
    },
    options: {
      plugins: {
        legend: { display: true },
        annotation: { annotations }
      },
      scales: {
        x: { ticks: { maxTicksLimit: 8 } }
      }
    }
  };

  // QuickChart hosts chartjs plugin annotation by default; if not, chart still renders.
  return "https://quickchart.io/chart?c=" + encodeURIComponent(JSON.stringify(qc));
}

// ========== Analysis prompt ==========
function stylePrompt(cfg, user) {
  const style = String(user.settings.style || "GENERAL").toUpperCase();
  if (style === "CUSTOM") {
    if (user.customPrompt?.ready && user.customPrompt.prompt) return user.customPrompt.prompt;
    return cfg.prompts.perStyle.GENERAL;
  }
  return cfg.prompts.perStyle[style] || cfg.prompts.perStyle.GENERAL;
}
function buildAnalysisPrompt(cfg, user, market, symbol, tf, snap, newsBundle) {
  const base = cfg.prompts.base || "";
  const styleP = stylePrompt(cfg, user);
  const risk = user.settings.risk || "متوسط";
  const newsOn = !!user.settings.news && !!cfg.features.newsEnabled;

  let newsText = "";
  if (newsOn && newsBundle?.items?.length) {
    const items = newsBundle.items.slice(0, 6).map((it) => `- ${it.title}`).join("\n");
    newsText = `\n\nاخبار مرتبط (برای اثرگذاری روی سناریو):\n${items}\n`;
  }

  return (
    `${base}\n\n` +
    `User style instruction:\n${styleP}\n\n` +
    `Market: ${market}\nSymbol: ${symbol}\nTimeframe: ${tf}\nRisk: ${risk}\n` +
    `Snapshot: lastClose=${snap.lastClose}, changePct=${snap.changePct.toFixed(2)}%, rangeHi=${snap.rangeHi}, rangeLo=${snap.rangeLo}\n` +
    `${newsText}\n` +
    "Output must be Persian, structured with headings:\n" +
    "1) خلاصه سریع\n2) بایاس و ساختار\n3) سطوح کلیدی\n4) سناریوها (اصلی/جایگزین)\n5) مدیریت ریسک و ابطال\n6) پلن کوتاه\n" +
    ZONES_SCHEMA_HINT
  );
}

// ========== Level quiz ==========
const LEVEL_QUESTIONS = [
  { id: "q1", q: "سطح تجربه‌ات در بازارهای مالی چقدر است؟ (مبتدی/متوسط/حرفه‌ای)" },
  { id: "q2", q: "بیشتر کدام سبک را می‌پسندی؟ (RTM/ICT/Price Action/General)" },
  { id: "q3", q: "در مدیریت ریسک، معمولا چقدر ریسک می‌کنی؟ (کم/متوسط/زیاد)" },
  { id: "q4", q: "هدف اصلی‌ات چیست؟ (اسکالپ/سوئینگ/بلندمدت)" }
];
async function evaluateLevelWithAI(env, cfg, answers) {
  const content =
    "با توجه به پاسخ‌های زیر سطح کاربر را تعیین کن و خروجی را به صورت JSON بده.\n" +
    "Schema: {level:\"beginner|intermediate|pro\", summary_fa:string, recommended_market:string, settings:{tf:string,risk:string,style:string,news:boolean}}\n" +
    "پاسخ‌ها:\n" +
    JSON.stringify(answers, null, 2);

  const r = await callAI(env, cfg, "level", [{ role: "user", content }], 15000);
  if (!r.ok) return { ok: false, error: r.error };

  const obj = extractLastJsonObject(r.text) || tryParseJson(r.text);
  if (!obj) return { ok: false, error: "AI JSON parse failed" };

  const lvl = String(obj.level || "").toLowerCase();
  const level = lvl.includes("pro") ? "pro" : lvl.includes("inter") ? "intermediate" : "beginner";

  const settings = obj.settings || {};
  return {
    ok: true,
    result: {
      level,
      summary_fa: String(obj.summary_fa || "").slice(0, 1200),
      recommended_market: String(obj.recommended_market || "CRYPTO").slice(0, 20),
      settings: {
        tf: String(settings.tf || "H1").toUpperCase(),
        risk: String(settings.risk || "متوسط"),
        style: String(settings.style || "GENERAL").toUpperCase(),
        news: !!settings.news
      }
    }
  };
}

// ========== Custom prompt ==========
async function generateCustomPrompt(env, cfg, strategyText) {
  const content =
    "تو یک مهندس پرامپت هستی. بر اساس استراتژی کاربر، یک Prompt عملی و دقیق برای تحلیل بازار بساز.\n" +
    "خروجی فقط متن پرامپت باشد (نه JSON).\n\n" +
    "استراتژی:\n" +
    String(strategyText || "").slice(0, 4500);

  const r = await callAI(env, cfg, "customprompt", [{ role: "user", content }], 15000);
  if (!r.ok) return { ok: false, error: r.error };
  return { ok: true, prompt: trunc(String(r.text || "").trim(), 2200) };
}

// ========== Telegram secret check ==========
function isTelegramSecretValid(request, env) {
  const expected = String(env.TELEGRAM_SECRET_TOKEN || "").trim();
  if (!expected) return true; // dev
  const got = request.headers.get("x-telegram-bot-api-secret-token") || "";
  return got === expected;
}

// ========== Telegram initData verification (MiniApp/Admin) ==========
async function hmacSha256(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, msgBytes);
  return new Uint8Array(sig);
}
async function verifyTelegramInitData(initData, botToken, maxAgeSec = 24 * 3600) {
  try {
    const params = new URLSearchParams(initData);
    const hash = params.get("hash");
    if (!hash) return { ok: false, error: "no_hash" };
    params.delete("hash");

    const pairs = [];
    for (const [k, v] of params.entries()) pairs.push([k, v]);
    pairs.sort((a, b) => a[0].localeCompare(b[0]));
    const dataCheckString = pairs.map(([k, v]) => `${k}=${v}`).join("\n");

    const secretKey = await hmacSha256(new TextEncoder().encode("WebAppData"), new TextEncoder().encode(botToken));
    const signature = await hmacSha256(secretKey, new TextEncoder().encode(dataCheckString));
    const sigHex = bytesToHex(signature);
    if (sigHex !== hash) return { ok: false, error: "bad_hash" };

    // Check auth_date
    const authDate = safeParseInt(params.get("auth_date"), 0);
    if (authDate > 0) {
      const age = Math.floor(nowMs() / 1000) - authDate;
      if (age > maxAgeSec) return { ok: false, error: "expired_init_data" };
    }

    const userJson = params.get("user");
    const user = userJson ? JSON.parse(userJson) : null;
    return { ok: true, user };
  } catch {
    return { ok: false, error: "verify_error" };
  }
}
async function authFromRequest(request, env, cfg) {
  // Bearer token for non-telegram admin usage
  const bearer = request.headers.get("authorization") || "";
  const adminToken = String(env.ADMIN_BEARER_TOKEN || "").trim();
  if (adminToken && bearer === `Bearer ${adminToken}`) {
    return { ok: true, via: "bearer", userId: "bearer", role: "owner", user: { id: 0, username: "bearer" } };
  }

  const initData = request.headers.get("x-telegram-init-data") || request.headers.get("x-init-data") || "";
  const botToken = String(env.BOT_TOKEN || "").trim();
  if (!initData || !botToken) return { ok: false, error: "no_init_data" };

  const v = await verifyTelegramInitData(initData, botToken);
  if (!v.ok || !v.user) return { ok: false, error: v.error || "bad_init" };

  const uid = String(v.user.id);
  return { ok: true, via: "initData", userId: uid, role: roleOf(env, uid), user: v.user };
}

// ========== MiniApp HTML (root "/") ==========
function miniAppHtml() {
  return `<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Market IQ MiniApp</title>
<style>
:root{--bg:#0b1220;--card:rgba(255,255,255,.06);--border:rgba(255,255,255,.10);--txt:#e8eefc;--muted:rgba(255,255,255,.75)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font-family:system-ui,-apple-system,Segoe UI,Roboto}
header{padding:14px 16px;border-bottom:1px solid var(--border);display:flex;gap:10px;align-items:center;justify-content:space-between}
h1{font-size:14px;margin:0}
main{padding:16px;display:grid;gap:12px;max-width:980px;margin:0 auto}
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:14px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.btn{cursor:pointer;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.09);color:#fff;padding:10px 12px;border-radius:12px}
.btn:active{transform:scale(.99)}
.small{font-size:12px;opacity:.85}
input,select,textarea{width:100%;padding:10px;border-radius:12px;border:1px solid rgba(255,255,255,.18);background:rgba(0,0,0,.25);color:#fff;outline:none}
pre{white-space:pre-wrap;word-break:break-word;background:rgba(0,0,0,.25);padding:10px;border-radius:12px;border:1px solid rgba(255,255,255,.12);margin:0}
.progress{height:10px;background:rgba(255,255,255,.10);border-radius:999px;overflow:hidden}
.progress>div{height:10px;background:rgba(255,255,255,.55);width:0%}
a{color:#9dd1ff}
hr{border:none;border-top:1px solid rgba(255,255,255,.10);margin:10px 0}
.badge{display:inline-block;padding:4px 8px;border-radius:999px;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);font-size:11px}
</style>
</head>
<body>
<header>
  <div>
    <h1>Market IQ — MiniApp</h1>
    <div class="small" id="status">...</div>
  </div>
  <div class="row">
    <button class="btn" id="refresh">⟳ بروزرسانی</button>
    <a class="btn" href="/admin" style="text-decoration:none">پنل ادمین</a>
  </div>
</header>

<main>
  <div class="card" id="banner" style="display:none"></div>

  <div class="card">
    <div class="row" style="justify-content:space-between">
      <div>
        <div><b id="name">کاربر</b> <span class="badge" id="role">user</span> <span class="small" id="sub">اشتراک: -</span></div>
        <div class="small">امتیاز: <span id="points">0</span> | دعوت موفق: <span id="invites">0</span> | کمیسیون: <span id="commission">0</span>%</div>
      </div>
      <div class="small">Version: ${VERSION}</div>
    </div>

    <div style="margin-top:10px">
      <div class="small">سهمیه روزانه</div>
      <div class="progress"><div id="pDaily"></div></div>
      <div class="small" id="tDaily"></div>
    </div>

    <div style="margin-top:10px">
      <div class="small">سهمیه ماهانه</div>
      <div class="progress"><div id="pMonth"></div></div>
      <div class="small" id="tMonth"></div>
    </div>
  </div>

  <div class="card">
    <h3 style="margin:0 0 8px 0;font-size:14px">تحلیل/سیگنال</h3>
    <div class="row">
      <select id="market">
        <option>CRYPTO</option><option>FOREX</option><option>METALS</option><option>STOCKS</option>
      </select>
      <input id="symbol" placeholder="Symbol مثل BTCUSDT / EURUSD / AAPL"/>
    </div>
    <div style="margin-top:10px" class="row">
      <button class="btn" id="analyze">📈 تحلیل</button>
      <button class="btn" id="newsBtn">📰 News</button>
      <button class="btn" id="copyRef">🎁 کد رفرال</button>
    </div>
    <div id="result" style="margin-top:10px"></div>
  </div>

  <div class="card">
    <h3 style="margin:0 0 8px 0;font-size:14px">تنظیمات</h3>
    <div class="row">
      <select id="tf"><option>M15</option><option>M30</option><option>H1</option><option>H4</option><option>D1</option></select>
      <select id="risk"><option>کم</option><option>متوسط</option><option>زیاد</option></select>
      <select id="style"><option>RTM</option><option>ICT</option><option>PRICE_ACTION</option><option>GENERAL</option><option>METHOD</option><option>CUSTOM</option></select>
      <label class="small"><input type="checkbox" id="newsToggle"/> News</label>
    </div>
    <div style="margin-top:10px" class="row">
      <button class="btn" id="saveSettings">💾 ذخیره</button>
      <span class="small" id="styleHint"></span>
    </div>
  </div>

  <div class="card">
    <h3 style="margin:0 0 8px 0;font-size:14px">کیف پول و درخواست‌ها</h3>
    <div class="small">آدرس برداشت (BEP20)</div>
    <input id="bep20" placeholder="0x... (BEP20)"/>
    <div style="margin-top:10px" class="row">
      <button class="btn" id="saveWallet">✅ ثبت کیف پول</button>
      <button class="btn" id="reqDeposit">➕ درخواست واریز</button>
      <button class="btn" id="reqWithdraw">➖ درخواست برداشت</button>
    </div>
    <div id="reqOut" style="margin-top:10px"></div>
  </div>

  <div class="card">
    <h3 style="margin:0 0 8px 0;font-size:14px">راهنما سریع</h3>
    <div class="small">
      • در تلگرام: /signals برای تحلیل — /buy برای خرید — /tx برای ثبت TXID — /support برای تیکت<br/>
      • اگر گزینه CUSTOM در تنظیمات غیرفعال است، ابتدا /customprompt را در تلگرام انجام بده.
    </div>
  </div>
</main>

<script>
(function(){
  const tg = window.Telegram && window.Telegram.WebApp ? window.Telegram.WebApp : null;
  const initData = tg ? tg.initData : "";
  const status = document.getElementById("status");

  function headers(){
    const h = {"content-type":"application/json"};
    if(initData) h["x-telegram-init-data"] = initData;
    const token = localStorage.getItem("admin_bearer");
    if(token) h["authorization"] = "Bearer " + token;
    return h;
  }

  async function api(path, body){
    const res = await fetch(path, {method: body ? "POST":"GET", headers: headers(), body: body?JSON.stringify(body):undefined});
    return await res.json().catch(()=>({ok:false,error:"bad_json"}));
  }

  function setEnergy(barId, textId, used, limit){
    if(limit===null || limit===undefined){ document.getElementById(barId).style.width="100%"; document.getElementById(textId).textContent="∞"; return; }
    const p = limit ? Math.min(100, Math.round((used/limit)*100)) : 0;
    document.getElementById(barId).style.width = p + "%";
    document.getElementById(textId).textContent = used + "/" + limit;
  }

  async function refresh(){
    status.textContent = "loading...";
    const prof = await api("/api/profile");
    if(!prof.ok){ status.textContent="auth error"; document.getElementById("result").innerHTML="<pre>"+JSON.stringify(prof,null,2)+"</pre>"; return; }

    document.getElementById("name").textContent = prof.profile.name || ("User " + prof.id);
    document.getElementById("role").textContent = prof.role;
    document.getElementById("points").textContent = prof.referral.points || 0;
    document.getElementById("invites").textContent = prof.referral.successfulInvites || 0;
    document.getElementById("commission").textContent = prof.referral.commissionPct || 0;
    document.getElementById("sub").textContent = "اشتراک: " + (prof.subscription.active ? "فعال" : "غیرفعال");

    setEnergy("pDaily","tDaily", prof.quota.dailyUsed, prof.quota.dailyLimit);
    setEnergy("pMonth","tMonth", prof.quota.monthlyUsed, prof.quota.monthlyLimit);

    const st = await api("/api/settings");
    document.getElementById("tf").value = st.settings.tf;
    document.getElementById("risk").value = st.settings.risk;
    document.getElementById("style").value = st.settings.style;
    document.getElementById("newsToggle").checked = !!st.settings.news;
    document.getElementById("styleHint").textContent = st.hints && st.hints.customReady===false ? "CUSTOM هنوز آماده نیست (در تلگرام /customprompt)" : "";

    const banner = st.banner;
    const b = document.getElementById("banner");
    if(banner && banner.enabled){
      b.style.display = "block";
      b.innerHTML = "<b>🎁 "+banner.text+"</b><div class='small'><a href='"+banner.link+"' target='_blank'>"+banner.link+"</a></div>";
    } else b.style.display = "none";

    document.getElementById("bep20").value = prof.wallet.bep20 || "";
    status.textContent = "ok";
  }

  document.getElementById("refresh").onclick = refresh;

  document.getElementById("saveSettings").onclick = async () => {
    const body = {
      tf: document.getElementById("tf").value,
      risk: document.getElementById("risk").value,
      style: document.getElementById("style").value,
      news: document.getElementById("newsToggle").checked
    };
    const r = await api("/api/settings", body);
    document.getElementById("result").innerHTML = "<pre>"+JSON.stringify(r,null,2)+"</pre>";
    refresh();
  };

  document.getElementById("analyze").onclick = async () => {
    const market = document.getElementById("market").value;
    const symbol = document.getElementById("symbol").value.trim();
    const r = await api("/api/signals", {market, symbol});
    let html = "<pre>"+(r.text || JSON.stringify(r,null,2))+"</pre>";
    if(r.chartUrl) html += "<hr/><div><a href='"+r.chartUrl+"' target='_blank'>Open Chart</a></div><img style='width:100%;margin-top:8px;border-radius:12px;border:1px solid rgba(255,255,255,.15)' src='"+r.chartUrl+"'/>";
    document.getElementById("result").innerHTML = html;
    refresh();
  };

  document.getElementById("newsBtn").onclick = async () => {
    const market = document.getElementById("market").value;
    const symbol = document.getElementById("symbol").value.trim();
    const r = await api("/api/news?market="+encodeURIComponent(market)+"&symbol="+encodeURIComponent(symbol));
    document.getElementById("result").innerHTML = "<pre>"+(r.summary_fa || r.summary || JSON.stringify(r,null,2))+"</pre>";
  };

  document.getElementById("copyRef").onclick = async () => {
    const r = await api("/api/profile");
    const code = r && r.referral ? r.referral.code : "";
    if(code){
      try{ await navigator.clipboard.writeText(code); }catch(e){}
      document.getElementById("result").innerHTML = "<pre>کد رفرال کپی شد: "+code+"\\n(به دوستت بگو /start "+code+" و Share Contact)</pre>";
    }
  };

  document.getElementById("saveWallet").onclick = async () => {
    const addr = document.getElementById("bep20").value.trim();
    const r = await api("/api/wallet", {bep20: addr});
    document.getElementById("reqOut").innerHTML = "<pre>"+JSON.stringify(r,null,2)+"</pre>";
    refresh();
  };

  document.getElementById("reqDeposit").onclick = async () => {
    const r = await api("/api/requests", {kind:"deposit", amount:"", note:"deposit request"});
    document.getElementById("reqOut").innerHTML = "<pre>"+JSON.stringify(r,null,2)+"</pre>";
  };

  document.getElementById("reqWithdraw").onclick = async () => {
    const r = await api("/api/requests", {kind:"withdraw", amount:"", note:"withdraw request"});
    document.getElementById("reqOut").innerHTML = "<pre>"+JSON.stringify(r,null,2)+"</pre>";
  };

  refresh();
})();
</script>
</body>
</html>`;
}

// ========== Admin HTML ==========
function adminHtml() {
  return `<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Market IQ Admin</title>
<style>
:root{--bg:#0b1220;--card:rgba(255,255,255,.06);--border:rgba(255,255,255,.10);--txt:#e8eefc}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font-family:system-ui,-apple-system,Segoe UI,Roboto}
header{padding:14px 16px;border-bottom:1px solid var(--border);display:flex;gap:10px;align-items:center;justify-content:space-between}
h1{font-size:14px;margin:0}
main{padding:16px;display:grid;gap:12px;max-width:1100px;margin:0 auto}
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:14px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.btn{cursor:pointer;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.09);color:#fff;padding:10px 12px;border-radius:12px}
.small{font-size:12px;opacity:.85}
input,textarea,select{width:100%;padding:10px;border-radius:12px;border:1px solid rgba(255,255,255,.18);background:rgba(0,0,0,.25);color:#fff;outline:none}
pre{white-space:pre-wrap;word-break:break-word;background:rgba(0,0,0,.25);padding:10px;border-radius:12px;border:1px solid rgba(255,255,255,.12);margin:0}
table{width:100%;border-collapse:collapse}
td,th{border-bottom:1px solid rgba(255,255,255,.10);padding:8px;text-align:right;font-size:12px}
a{color:#9dd1ff}
.badge{display:inline-block;padding:4px 8px;border-radius:999px;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);font-size:11px}
</style>
</head>
<body>
<header>
  <div>
    <h1>Market IQ — Admin Panel</h1>
    <div class="small" id="status">...</div>
  </div>
  <div class="row">
    <a class="btn" href="/" style="text-decoration:none">MiniApp</a>
    <button class="btn" id="login">🔑 Bearer Token</button>
    <span class="badge" id="role">-</span>
  </div>
</header>

<main>
  <div class="card">
    <div class="row">
      <button class="btn" id="loadCfg">⟳ Load Config</button>
      <button class="btn" id="saveCfg">💾 Save Config</button>
      <button class="btn" id="reports">📊 Reports</button>
      <button class="btn" id="users">👥 Users</button>
      <button class="btn" id="payments">💳 Payments</button>
      <button class="btn" id="tickets">🆘 Tickets</button>
      <button class="btn" id="requests">📌 Requests</button>
      <button class="btn" id="audit">🧾 Audit</button>
      <button class="btn" id="broadcast">📣 Broadcast</button>
    </div>
    <div class="small">نکته: بعضی فیلدها Owner-only هستند (Wallet/Prompts/Styles/Points/Commission/News Sources/Security).</div>
  </div>

  <div class="card">
    <h3 style="margin:0 0 8px 0;font-size:14px">Config Editor</h3>

    <div class="row">
      <div style="flex:1;min-width:240px">
        <label class="small">Public Wallet (Owner-only)</label>
        <input id="walletPublic" placeholder="0x..."/>
      </div>
      <div style="flex:1;min-width:160px">
        <label class="small">Sub Price USDT</label>
        <input id="subPrice" type="number" step="0.1"/>
      </div>
      <div style="flex:1;min-width:160px">
        <label class="small">Sub Duration Days</label>
        <input id="subDays" type="number"/>
      </div>
      <div style="flex:1;min-width:160px">
        <label class="small">Sub Daily Limit</label>
        <input id="subLimit" type="number"/>
      </div>
    </div>

    <div class="row" style="margin-top:10px">
      <div style="flex:1;min-width:160px">
        <label class="small">Free Daily</label>
        <input id="freeDaily" type="number"/>
      </div>
      <div style="flex:1;min-width:160px">
        <label class="small">Free Monthly</label>
        <input id="freeMonthly" type="number"/>
      </div>
      <div style="flex:1;min-width:160px">
        <label class="small">Banner Enabled</label>
        <select id="bannerEnabled"><option value="true">true</option><option value="false">false</option></select>
      </div>
    </div>

    <div class="row" style="margin-top:10px">
      <div style="flex:1;min-width:240px">
        <label class="small">Banner Text</label>
        <input id="bannerText"/>
      </div>
      <div style="flex:1;min-width:240px">
        <label class="small">Banner Link</label>
        <input id="bannerLink"/>
      </div>
    </div>

    <div style="margin-top:10px">
      <label class="small">Base Prompt (Owner-only recommended)</label>
      <textarea id="basePrompt" rows="5"></textarea>
    </div>

    <div style="margin-top:10px">
      <label class="small">Vision Prompt (Owner-only recommended)</label>
      <textarea id="visionPrompt" rows="4"></textarea>
    </div>

    <div style="margin-top:10px">
      <label class="small">Per-Style Prompts (JSON, Owner-only)</label>
      <textarea id="perStyle" rows="6"></textarea>
    </div>

    <div style="margin-top:10px">
      <label class="small">Styles (JSON, Owner-only)</label>
      <textarea id="stylesJson" rows="6"></textarea>
    </div>

    <div style="margin-top:10px">
      <label class="small">News (JSON, Owner-only) — rss/noiseFilters/ttlMs</label>
      <textarea id="newsJson" rows="6"></textarea>
    </div>

    <div class="row" style="margin-top:10px">
      <div style="flex:1;min-width:160px">
        <label class="small">Points per invite (Owner-only)</label>
        <input id="pInvite" type="number"/>
      </div>
      <div style="flex:1;min-width:160px">
        <label class="small">Redeem free sub points (Owner-only)</label>
        <input id="pRedeem" type="number"/>
      </div>
      <div style="flex:1;min-width:160px">
        <label class="small">Buy sub points (Owner-only)</label>
        <input id="pBuy" type="number"/>
      </div>
    </div>

    <div class="row" style="margin-top:10px">
      <div style="flex:1;min-width:160px">
        <label class="small">Commission step % (Owner-only)</label>
        <input id="cStep" type="number"/>
      </div>
      <div style="flex:1;min-width:160px">
        <label class="small">Commission max % (Owner-only)</label>
        <input id="cMax" type="number"/>
      </div>
    </div>

    <div class="row" style="margin-top:10px">
      <div style="flex:1;min-width:160px">
        <label class="small">Feature flags (JSON)</label>
        <textarea id="featuresJson" rows="3"></textarea>
      </div>
      <div style="flex:1;min-width:160px">
        <label class="small">Security (JSON, Owner-only)</label>
        <textarea id="securityJson" rows="3"></textarea>
      </div>
    </div>

    <div class="row" style="margin-top:10px">
      <div style="flex:1;min-width:160px">
        <label class="small">Rollback config (Owner-only) — verKey</label>
        <input id="rollbackKey" placeholder="marketiq:config:ver:...."/>
      </div>
      <button class="btn" id="rollbackBtn">⟲ Rollback</button>
    </div>
  </div>

  <div class="card">
    <h3 style="margin:0 0 8px 0;font-size:14px">Output</h3>
    <pre id="out"></pre>
  </div>
</main>

<script>
(function(){
  const tg = window.Telegram && window.Telegram.WebApp ? window.Telegram.WebApp : null;
  const initData = tg ? tg.initData : "";
  const status = document.getElementById("status");
  const out = document.getElementById("out");
  const roleBadge = document.getElementById("role");

  function headers(){
    const h={"content-type":"application/json"};
    if(initData) h["x-telegram-init-data"]=initData;
    const token = localStorage.getItem("admin_bearer");
    if(token) h["authorization"]="Bearer "+token;
    return h;
  }

  function setOut(x){ out.textContent = typeof x==="string" ? x : JSON.stringify(x,null,2); }

  async function api(path, body){
    const res = await fetch(path, {method: body ? "POST":"GET", headers: headers(), body: body?JSON.stringify(body):undefined});
    return await res.json().catch(()=>({ok:false,error:"bad_json"}));
  }

  async function whoami(){
    const r = await api("/api/admin/whoami");
    roleBadge.textContent = r && r.ok ? r.role : "unauth";
  }

  async function loadCfg(){
    status.textContent="loading...";
    const r = await api("/api/admin/config/get");
    if(!r.ok){ status.textContent="auth/error"; setOut(r); return; }
    const c = r.cfg;

    document.getElementById("walletPublic").value = c.walletPublic || "";
    document.getElementById("subPrice").value = c.subscription.priceUSDT;
    document.getElementById("subDays").value = c.subscription.durationDays;
    document.getElementById("subLimit").value = c.subscription.dailyLimit;

    document.getElementById("freeDaily").value = c.limits.freeDaily;
    document.getElementById("freeMonthly").value = c.limits.freeMonthly;

    document.getElementById("bannerEnabled").value = String(!!c.banner.enabled);
    document.getElementById("bannerText").value = c.banner.text || "";
    document.getElementById("bannerLink").value = c.banner.link || "";

    document.getElementById("basePrompt").value = c.prompts.base || "";
    document.getElementById("visionPrompt").value = c.prompts.vision || "";
    document.getElementById("perStyle").value = JSON.stringify(c.prompts.perStyle || {}, null, 2);
    document.getElementById("stylesJson").value = JSON.stringify(c.styles || {}, null, 2);
    document.getElementById("newsJson").value = JSON.stringify(c.news || {}, null, 2);

    document.getElementById("pInvite").value = c.points.perInvite;
    document.getElementById("pRedeem").value = c.points.redeemFreeSub;
    document.getElementById("pBuy").value = c.points.buySub;

    document.getElementById("cStep").value = c.commission.stepPct;
    document.getElementById("cMax").value = c.commission.maxPct;

    document.getElementById("featuresJson").value = JSON.stringify(c.features || {}, null, 2);
    document.getElementById("securityJson").value = JSON.stringify(c.security || {}, null, 2);

    status.textContent="ok";
    setOut({ok:true, hint:"Loaded. Owner-only fields will be ignored if you're not Owner."});
  }

  async function saveCfg(){
    status.textContent="saving...";
    let perStyle={}, stylesJson={}, newsJson={}, featuresJson={}, securityJson={};
    try{ perStyle = JSON.parse(document.getElementById("perStyle").value || "{}"); }catch(e){ setOut("Invalid perStyle JSON"); status.textContent="error"; return; }
    try{ stylesJson = JSON.parse(document.getElementById("stylesJson").value || "{}"); }catch(e){ setOut("Invalid styles JSON"); status.textContent="error"; return; }
    try{ newsJson = JSON.parse(document.getElementById("newsJson").value || "{}"); }catch(e){ setOut("Invalid news JSON"); status.textContent="error"; return; }
    try{ featuresJson = JSON.parse(document.getElementById("featuresJson").value || "{}"); }catch(e){ setOut("Invalid features JSON"); status.textContent="error"; return; }
    try{ securityJson = JSON.parse(document.getElementById("securityJson").value || "{}"); }catch(e){ setOut("Invalid security JSON"); status.textContent="error"; return; }

    const patch = {
      walletPublic: document.getElementById("walletPublic").value.trim(),
      subscription: {
        priceUSDT: Number(document.getElementById("subPrice").value),
        durationDays: Number(document.getElementById("subDays").value),
        dailyLimit: Number(document.getElementById("subLimit").value)
      },
      limits: {
        freeDaily: Number(document.getElementById("freeDaily").value),
        freeMonthly: Number(document.getElementById("freeMonthly").value)
      },
      banner: {
        enabled: document.getElementById("bannerEnabled").value === "true",
        text: document.getElementById("bannerText").value,
        link: document.getElementById("bannerLink").value
      },
      prompts: {
        base: document.getElementById("basePrompt").value,
        vision: document.getElementById("visionPrompt").value,
        perStyle
      },
      styles: stylesJson,
      news: newsJson,
      points: {
        perInvite: Number(document.getElementById("pInvite").value),
        redeemFreeSub: Number(document.getElementById("pRedeem").value),
        buySub: Number(document.getElementById("pBuy").value)
      },
      commission: {
        stepPct: Number(document.getElementById("cStep").value),
        maxPct: Number(document.getElementById("cMax").value)
      },
      features: featuresJson,
      security: securityJson
    };

    const r = await api("/api/admin/config/set", patch);
    setOut(r);
    status.textContent = r.ok ? "saved" : "error";
    if(r.ok) loadCfg();
  }

  async function doRollback(){
    const verKey = document.getElementById("rollbackKey").value.trim();
    if(!verKey){ setOut("verKey required"); return; }
    const r = await api("/api/admin/config/rollback", {verKey});
    setOut(r);
  }

  async function showReports(){
    const r = await api("/api/admin/reports/summary?days=14");
    setOut(r);
  }

  async function showUsers(){
    const r = await api("/api/admin/users/list?limit=50");
    setOut(r);
  }

  async function showPayments(){
    const r = await api("/api/admin/payments/list?status=pending&limit=50");
    setOut(r);
  }

  async function showTickets(){
    const r = await api("/api/admin/tickets/list?status=open&limit=50");
    setOut(r);
  }

  async function showRequests(){
    const r = await api("/api/admin/requests/list?status=open&limit=50");
    setOut(r);
  }

  async function showAudit(){
    const r = await api("/api/admin/audit/list?limit=50");
    setOut(r);
  }

  async function broadcast(){
    const msg = prompt("Broadcast message (Owner only):");
    if(!msg) return;
    const r = await api("/api/admin/broadcast/start", {text: msg});
    setOut(r);
  }

  document.getElementById("login").onclick = () => {
    const t = prompt("Paste ADMIN_BEARER_TOKEN (optional):");
    if(t){ localStorage.setItem("admin_bearer", t.trim()); alert("Saved in localStorage. Reload."); location.reload(); }
  };

  document.getElementById("loadCfg").onclick = loadCfg;
  document.getElementById("saveCfg").onclick = saveCfg;
  document.getElementById("rollbackBtn").onclick = doRollback;
  document.getElementById("reports").onclick = showReports;
  document.getElementById("users").onclick = showUsers;
  document.getElementById("payments").onclick = showPayments;
  document.getElementById("tickets").onclick = showTickets;
  document.getElementById("requests").onclick = showRequests;
  document.getElementById("audit").onclick = showAudit;
  document.getElementById("broadcast").onclick = broadcast;

  whoami();
  loadCfg();
})();
</script>
</body>
</html>`;
}

// ========== Responses ==========
function jsonResponse(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers }
  });
}
function htmlResponse(html, status = 200) {
  return new Response(html, {
    status,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }
  });
}
function textResponse(text, status = 200, headers = {}) {
  return new Response(String(text), { status, headers: { "content-type": "text/plain; charset=utf-8", ...headers } });
}

// ========== MiniApp APIs ==========
async function handleMiniAppApi(request, env, cfg) {
  const url = new URL(request.url);
  const path = url.pathname;

  const auth = await authFromRequest(request, env, cfg);
  if (!auth.ok) return jsonResponse({ ok: false, error: auth.error || "unauthorized" }, 401);

  const userId = auth.userId === "bearer" ? "" : String(auth.userId);
  const user = userId ? await ensureUser(env, userId) : null;
  if (!user) return jsonResponse({ ok: false, error: "no_user" }, 400);

  // Rate limit API per-user
  const rl = await rateLimitAllow(env, cfg, "api", userId, cfg.security.rlWebhookPerMin);
  if (!rl.ok) return jsonResponse({ ok: false, error: "rate_limited" }, 429);

  if (isBanned(user)) {
    return jsonResponse({ ok: false, error: "banned", until: user.moderation.bannedUntil, reason: user.moderation.banReason }, 403);
  }

  if (path === "/api/profile") {
    const view = computeQuotaView(env, cfg, user, userId);
    return jsonResponse({
      ok: true,
      id: user.id,
      role: roleOf(env, userId),
      profile: user.profile,
      settings: user.settings,
      referral: user.referral,
      subscription: user.subscription,
      wallet: user.wallet,
      quota: {
        dailyUsed: view.dailyUsed,
        dailyLimit: Number.isFinite(view.dailyLimit) ? view.dailyLimit : null,
        monthlyUsed: view.monthlyUsed,
        monthlyLimit: view.monthlyLimit
      }
    });
  }

  if (path === "/api/settings") {
    if (request.method === "GET") {
      return jsonResponse({
        ok: true,
        settings: user.settings,
        banner: cfg.banner,
        styles: availableStylesForUser(cfg, user),
        hints: { customReady: !!user.customPrompt?.ready }
      });
    }
    const body = await request.json().catch(() => ({}));
    const tf = String(body.tf || user.settings.tf).toUpperCase();
    const risk = String(body.risk || user.settings.risk);
    const style = String(body.style || user.settings.style).toUpperCase();
    const news = !!body.news;

    user.settings.tf = ["M15", "M30", "H1", "H4", "D1"].includes(tf) ? tf : user.settings.tf;
    user.settings.risk = ["کم", "متوسط", "زیاد"].includes(risk) ? risk : user.settings.risk;

    const allowed = availableStylesForUser(cfg, user);
    user.settings.style = allowed.includes(style) ? style : user.settings.style;
    user.settings.news = news;

    await saveUser(env, user);
    return jsonResponse({ ok: true, settings: user.settings, styles: allowed, banner: cfg.banner });
  }

  if (path === "/api/news") {
    const market = url.searchParams.get("market") || (user.profile.favoriteMarket || "CRYPTO");
    const symbol = url.searchParams.get("symbol") || "";
    const bundle = await getNewsBundle(env, cfg, market, symbol);
    return jsonResponse({ ok: true, summary_fa: bundle.summary_fa, items: bundle.items || [], ranked: bundle.ranked || [] });
  }

  if (path === "/api/signals") {
    if (request.method !== "POST") return jsonResponse({ ok: false, error: "method_not_allowed" }, 405);
    const body = await request.json().catch(() => ({}));
    const market = String(body.market || user.profile.favoriteMarket || "CRYPTO").toUpperCase();
    const symbol = normalizeSymbolInput(body.symbol || "");
    if (!symbol) return jsonResponse({ ok: false, error: "invalid_symbol" }, 400);

    const rlA = await rateLimitAllow(env, cfg, "analyze", userId, cfg.security.rlAnalyzePerMin);
    if (!rlA.ok) return jsonResponse({ ok: false, error: "rate_limited_analyze" }, 429);

    if (!user.profile.onboardingDone && !user.moderation.phoneDuplicate) {
      return jsonResponse({ ok: false, error: "onboarding_required" }, 400);
    }
    if (user.moderation.phoneDuplicate) {
      return jsonResponse({ ok: false, error: "phone_duplicate_block", help: "برای فعالسازی با پشتیبانی تماس بگیر." }, 403);
    }

    const view = computeQuotaView(env, cfg, user, userId);
    if (!canConsumeQuota(view)) {
      return jsonResponse({ ok: false, error: "quota_exceeded", quota: view }, 429);
    }

    try {
      const candles = await getCandlesWithFallback(env, cfg, market, symbol, user.settings.tf);
      const snap = snapshotFromCandles(candles);

      let newsBundle = null;
      if (user.settings.news && cfg.features.newsEnabled) newsBundle = await getNewsBundle(env, cfg, market, symbol);

      const prompt = buildAnalysisPrompt(cfg, user, market, symbol, user.settings.tf, snap, newsBundle);
      const ai = await callAI(env, cfg, "analysis", [{ role: "user", content: prompt }], 20000);

      let analysisText = "";
      let zones = [];
      if (ai.ok) {
        analysisText = String(ai.text || "");
        let zonesObj = extractLastJsonObject(analysisText);
        let val = validateZones(zonesObj);
        if (!val.ok) {
          const repaired = await repairZonesJsonOnce(env, cfg, analysisText);
          val = validateZones(repaired);
        }
        zones = val.ok ? val.zones : [];
        if (zonesObj) {
          const idx = analysisText.lastIndexOf("{");
          if (idx > 0) analysisText = analysisText.slice(0, idx).trim();
        }
      } else {
        analysisText = "AI در دسترس نیست یا خطا داد: " + (ai.error || "unknown");
      }

      const chartUrl = cfg.features.chartEnabled ? buildChartUrl(cfg, symbol, user.settings.tf, candles, zones) : "";

      consumeQuota(user, view);
      user.stats.analysisCount = safeParseInt(user.stats.analysisCount, 0) + 1;
      user.stats.lastAnalysisAt = nowMs();
      await saveUser(env, user);
      await metricInc(env, "analyses", 1);

      return jsonResponse({
        ok: true,
        text: trunc(analysisText, 3500),
        chartUrl,
        zones,
        news: newsBundle ? { summary_fa: newsBundle.summary_fa, items: newsBundle.items } : null,
        quota: computeQuotaView(env, cfg, user, userId)
      });
    } catch (e) {
      return jsonResponse({ ok: false, error: "signals_error", detail: String(e?.message || e) }, 500);
    }
  }

  if (path === "/api/wallet") {
    if (request.method === "GET") return jsonResponse({ ok: true, wallet: user.wallet });
    const body = await request.json().catch(() => ({}));
    const addr = String(body.bep20 || "").trim();
    user.wallet.bep20 = addr;
    await saveUser(env, user);
    return jsonResponse({ ok: true, wallet: user.wallet });
  }

  if (path === "/api/requests") {
    if (request.method !== "POST") return jsonResponse({ ok: false, error: "method_not_allowed" }, 405);
    const body = await request.json().catch(() => ({}));
    const kind = String(body.kind || "");
    if (!["deposit", "withdraw"].includes(kind)) return jsonResponse({ ok: false, error: "bad_kind" }, 400);
    if (kind === "withdraw" && !String(user.wallet.bep20 || "").trim()) return jsonResponse({ ok: false, error: "no_bep20_wallet" }, 400);

    const req = await createRequest(env, userId, kind, { amount: String(body.amount || ""), note: String(body.note || "") });
    await notifyStaff(env, `📌 درخواست جدید (${kind})\nUser: ${userId}\nReq: ${req.id}\nWallet: ${user.wallet.bep20 || "-"}`);
    return jsonResponse({ ok: true, req });
  }

  return jsonResponse({ ok: false, error: "not_found" }, 404);
}

// ========== Admin APIs ==========
function maskUserForAdmin(role, u) {
  const owner = role === "owner";
  return {
    id: u.id,
    createdAt: u.createdAt,
    lastSeenAt: u.lastSeenAt,
    profile: {
      onboardingDone: !!u.profile?.onboardingDone,
      name: u.profile?.name || "",
      phone: owner ? (u.profile?.phone || "") : maskPhone(u.profile?.phone || ""),
      experience: u.profile?.experience || "",
      favoriteMarket: u.profile?.favoriteMarket || ""
    },
    settings: u.settings || {},
    referral: u.referral || {},
    subscription: u.subscription || {},
    wallet: {
      bep20: owner ? (u.wallet?.bep20 || "") : (u.wallet?.bep20 ? (String(u.wallet.bep20).slice(0, 6) + "…") : "")
    },
    moderation: owner ? u.moderation : { bannedUntil: u.moderation?.bannedUntil || 0, phoneDuplicate: !!u.moderation?.phoneDuplicate }
  };
}

async function handleAdminApi(request, env, cfg) {
  const url = new URL(request.url);
  const path = url.pathname;

  const auth = await authFromRequest(request, env, cfg);
  if (!auth.ok) return jsonResponse({ ok: false, error: "unauthorized" }, 401);

  const uid = auth.userId === "bearer" ? "bearer" : String(auth.userId);
  const role = auth.userId === "bearer" ? "owner" : roleOf(env, uid);

  // Rate limit admin calls
  const rl = await rateLimitAllow(env, cfg, "admin", uid, cfg.security.rlAdminPerMin);
  if (!rl.ok) return jsonResponse({ ok: false, error: "rate_limited" }, 429);

  if (!(role === "admin" || role === "owner")) return jsonResponse({ ok: false, error: "forbidden" }, 403);

  if (path === "/api/admin/whoami") {
    return jsonResponse({ ok: true, role, userId: uid });
  }

  if (path === "/api/admin/config/get") {
    return jsonResponse({ ok: true, cfg });
  }

  if (path === "/api/admin/config/set" && request.method === "POST") {
    const patch = await request.json().catch(() => ({}));
    const next = applyConfigPatchWithRBAC(env, role, cfg, patch);
    const saved = await saveConfig(env, uid, next, "config_set");
    // Alarm on wallet change (owner notify always; staff notify as well)
    if (patch?.walletPublic) {
      await notifyOwners(env, `🚨 هشدار: تغییر ولت عمومی توسط ${uid}\nWallet: ${String(patch.walletPublic).trim()}`);
      await notifyStaff(env, `ℹ️ ولت عمومی تغییر کرد.\nBy: ${uid}\nWallet: ${String(patch.walletPublic).trim()}`);
    }
    return jsonResponse({ ok: true, cfg: saved, note: role === "admin" ? "Owner-only fields ignored for admin." : "Saved." });
  }

  if (path === "/api/admin/config/rollback" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const verKey = String(body.verKey || "").trim();
    const r = await rollbackConfig(env, uid, verKey);
    return jsonResponse(r.ok ? r : { ok: false, error: r.error }, r.ok ? 200 : 403);
  }

  if (path === "/api/admin/reports/summary") {
    const days = safeParseInt(url.searchParams.get("days"), 14);
    // Admin can see limited; owner can see full (we return same structure)
    const rep = await getReportSummary(env, days);
    return jsonResponse({ ok: true, role, report: rep });
  }

  if (path === "/api/admin/users/list") {
    const limit = clamp(safeParseInt(url.searchParams.get("limit"), 50), 1, 200);
    const cursor = url.searchParams.get("cursor") || "";
    const full = url.searchParams.get("full") === "1";
    const isOwner = role === "owner";
    if (full && !isOwner) return jsonResponse({ ok: false, error: "owner_only_full" }, 403);

    const r = await kvList(env, `${KV_PREFIX}user:`, limit, cursor || undefined);
    const users = [];
    for (const k of r.keys) {
      const u = await kvGetJson(env, k.name);
      if (u) users.push(maskUserForAdmin(role, u));
    }
    return jsonResponse({ ok: true, role, users, cursor: r.cursor || "" });
  }

  if (path === "/api/admin/users/get") {
    const id = url.searchParams.get("id") || "";
    if (!id) return jsonResponse({ ok: false, error: "id_required" }, 400);
    const u = await kvGetJson(env, kUser(id));
    if (!u) return jsonResponse({ ok: false, error: "not_found" }, 404);
    return jsonResponse({ ok: true, user: maskUserForAdmin(role, u) });
  }

  if (path === "/api/admin/users/ban" && request.method === "POST") {
    if (role !== "owner") return jsonResponse({ ok: false, error: "owner_only" }, 403);
    const body = await request.json().catch(() => ({}));
    const id = String(body.id || "").trim();
    const hours = clamp(safeParseInt(body.hours, 24), 1, 24 * 365);
    const reason = String(body.reason || "ban").slice(0, 200);
    const u = await kvGetJson(env, kUser(id));
    if (!u) return jsonResponse({ ok: false, error: "not_found" }, 404);
    u.moderation = u.moderation || {};
    u.moderation.bannedUntil = nowMs() + hours * 3600 * 1000;
    u.moderation.banReason = reason;
    await saveUser(env, u);
    await auditLog(env, uid, "user_ban", null, null, { id, hours, reason });
    await tgSendMessage(env, id, `⛔️ شما مسدود شده‌اید.\nمدت: ${hours} ساعت\nدلیل: ${reason}\nاگر اشتباه است، /support`, mainMenuKeyboard());
    return jsonResponse({ ok: true });
  }

  if (path === "/api/admin/users/unban" && request.method === "POST") {
    if (role !== "owner") return jsonResponse({ ok: false, error: "owner_only" }, 403);
    const body = await request.json().catch(() => ({}));
    const id = String(body.id || "").trim();
    const u = await kvGetJson(env, kUser(id));
    if (!u) return jsonResponse({ ok: false, error: "not_found" }, 404);
    u.moderation = u.moderation || {};
    u.moderation.bannedUntil = 0;
    u.moderation.banReason = "";
    await saveUser(env, u);
    await auditLog(env, uid, "user_unban", null, null, { id });
    await tgSendMessage(env, id, "✅ محدودیت شما برداشته شد.", mainMenuKeyboard());
    return jsonResponse({ ok: true });
  }

  if (path === "/api/admin/payments/list") {
    const status = url.searchParams.get("status") || "pending";
    const limit = clamp(safeParseInt(url.searchParams.get("limit"), 50), 1, 200);
    const cursor = url.searchParams.get("cursor") || "";
    const r = await listPaymentsByStatus(env, status, limit, cursor);
    // mask txid for admin? operational needs full txid; keep full for staff (admin+owner).
    return jsonResponse({ ok: true, items: r.items, cursor: r.cursor || "" });
  }

  if (path === "/api/admin/payments/approve" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const txid = String(body.txid || "").trim();
    const r = await approvePayment(env, cfg, txid, uid);
    if (!r.ok) return jsonResponse({ ok: false, error: r.error }, 400);
    await tgSendMessage(env, r.user.id, `✅ پرداخت تایید شد. اشتراک فعال شد.\nتا: ${new Date(r.user.subscription.until).toISOString().slice(0, 10)}`, mainMenuKeyboard());
    return jsonResponse({ ok: true, payment: r.payment });
  }

  if (path === "/api/admin/payments/reject" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const txid = String(body.txid || "").trim();
    const reason = String(body.reason || "");
    const r = await rejectPayment(env, txid, uid, reason);
    if (!r.ok) return jsonResponse({ ok: false, error: r.error }, 400);
    await tgSendMessage(env, r.payment.userId, `❌ پرداخت رد شد.\nTXID: ${txid}\n${reason ? "دلیل: " + reason : ""}`, mainMenuKeyboard());
    return jsonResponse({ ok: true, payment: r.payment });
  }

  if (path === "/api/admin/tickets/list") {
    const status = url.searchParams.get("status") || "open";
    const limit = clamp(safeParseInt(url.searchParams.get("limit"), 50), 1, 200);
    const cursor = url.searchParams.get("cursor") || "";
    const r = await listTickets(env, status, limit, cursor);
    return jsonResponse({ ok: true, items: r.items, cursor: r.cursor || "" });
  }

  if (path === "/api/admin/tickets/reply" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const ticketId = String(body.ticketId || "");
    const reply = String(body.reply || "");
    const r = await replyTicket(env, ticketId, reply, uid);
    if (!r.ok) return jsonResponse({ ok: false, error: r.error }, 400);
    await tgSendMessage(env, r.ticket.fromUserId, `✅ پاسخ پشتیبانی:\n\n${reply}`, mainMenuKeyboard());
    return jsonResponse({ ok: true, ticket: r.ticket });
  }

  if (path === "/api/admin/requests/list") {
    const status = url.searchParams.get("status") || "open";
    const limit = clamp(safeParseInt(url.searchParams.get("limit"), 50), 1, 200);
    const cursor = url.searchParams.get("cursor") || "";
    const r = await listRequests(env, status, limit, cursor);
    // Mask wallets for admin (owner full)
    const items = r.items.map((x) => {
      if (role === "owner") return x;
      const copy = { ...x, payload: { ...x.payload } };
      if (copy.payload?.wallet) copy.payload.wallet = String(copy.payload.wallet).slice(0, 6) + "…";
      return copy;
    });
    return jsonResponse({ ok: true, items, cursor: r.cursor || "" });
  }

  if (path === "/api/admin/requests/done" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const reqId = String(body.reqId || "");
    const note = String(body.note || "");
    const r = await markRequestDone(env, reqId, uid, note);
    if (!r.ok) return jsonResponse({ ok: false, error: r.error }, 400);
    await tgSendMessage(env, r.req.userId, `✅ درخواست شما انجام شد.\nReq: ${r.req.id}\n${note ? "Note: " + note : ""}`, mainMenuKeyboard());
    return jsonResponse({ ok: true, req: r.req });
  }

  if (path === "/api/admin/audit/list") {
    if (role !== "owner") return jsonResponse({ ok: false, error: "owner_only" }, 403);
    const limit = clamp(safeParseInt(url.searchParams.get("limit"), 50), 1, 200);
    const cursor = url.searchParams.get("cursor") || "";
    const r = await kvList(env, `${KV_PREFIX}auditidx:`, limit, cursor || undefined);
    const keys = r.keys.map((k) => k.name.replace(`${KV_PREFIX}auditidx:`, `${KV_PREFIX}audit:`));
    const items = [];
    for (const key of keys) {
      const a = await kvGetJson(env, key);
      if (a) items.push(a);
    }
    items.sort((a, b) => (b.ts || 0) - (a.ts || 0));
    return jsonResponse({ ok: true, items, cursor: r.cursor || "" });
  }

  if (path === "/api/admin/broadcast/start" && request.method === "POST") {
    if (role !== "owner") return jsonResponse({ ok: false, error: "owner_only" }, 403);
    if (!cfg.features.broadcastEnabled) return jsonResponse({ ok: false, error: "broadcast_disabled" }, 400);

    const body = await request.json().catch(() => ({}));
    const text = String(body.text || "").trim();
    if (!text) return jsonResponse({ ok: false, error: "text_required" }, 400);

    const jobId = `${nowMs()}-${randomToken(6)}`;
    const job = {
      id: jobId,
      createdAt: nowMs(),
      status: "running",
      cursor: "",
      sent: 0,
      failed: 0,
      text: trunc(text, 3500)
    };
    await kvPutJson(env, kBroadcastJob(jobId), job, { expirationTtl: 7 * 24 * 3600 });
    await auditLog(env, uid, "broadcast_start", null, null, { jobId, preview: trunc(text, 200) });

    return jsonResponse({ ok: true, jobId, job });
  }

  return jsonResponse({ ok: false, error: "not_found" }, 404);
}

// ========== Broadcast job processing ==========
async function processBroadcastJobs(env, cfg) {
  // find jobs by listing prefix job:broadcast:
  const prefix = `${KV_PREFIX}job:broadcast:`;
  const r = await kvList(env, prefix, 10, undefined);
  for (const k of r.keys) {
    const job = await kvGetJson(env, k.name);
    if (!job || job.status !== "running") continue;

    // send to users in pages
    const batchSize = 30;
    const list = await kvList(env, `${KV_PREFIX}user:`, batchSize, job.cursor || undefined);
    const keys = list.keys || [];
    for (const uk of keys) {
      const u = await kvGetJson(env, uk.name);
      if (!u?.id) continue;
      try {
        await tgSendMessage(env, u.id, job.text, mainMenuKeyboard());
        job.sent++;
      } catch {
        job.failed++;
      }
    }
    job.cursor = list.cursor || "";
    if (!job.cursor || keys.length === 0) job.status = "done";
    job.updatedAt = nowMs();
    await kvPutJson(env, k.name, job, { expirationTtl: 7 * 24 * 3600 });
  }
}

// ========== Telegram Core flows ==========
function welcomeText(env) {
  return (
    `سلام! من ${botName(env)} هستم 🤖📈\n\n` +
    "• تحلیل/سیگنال با چارت زون‌دار (Demand/Supply)\n" +
    "• مدیریت سهمیه و اشتراک\n" +
    "• رفرال و امتیاز\n" +
    "• News (اختیاری)\n\n" +
    "از منو استفاده کن یا /signals را بزن."
  );
}

// Onboarding
async function startOnboarding(env, cfg, chatId, userId, user) {
  user.state.flow = "onb_name";
  user.state.data = {};
  await saveUser(env, user);
  await tgSendMessage(env, chatId, "برای شروع، لطفاً نامت رو بفرست 🙂", backToMenuKeyboard());
}
async function handleContact(env, cfg, chatId, userId, user, contact) {
  const phone = normalizePhone(contact.phone_number || "");
  if (!phone) {
    await tgSendMessage(env, chatId, "شماره معتبر نبود. لطفاً دوباره Share Contact را بزن.", contactKeyboard());
    return;
  }

  const dup = await isPhoneDuplicate(env, phone, userId);
  if (dup) {
    user.profile.phone = phone;
    user.profile.onboardingDone = false;
    user.moderation.phoneDuplicate = true;
    user.referral.referredBy = ""; // disable referral
    user.state.flow = "idle";
    await saveUser(env, user);

    await tgSendMessage(
      env,
      chatId,
      ensureBackHint("این شماره قبلاً ثبت شده است. برای امنیت، امکان ادامه onboarding/رفرال با این شماره وجود ندارد.\nبرای فعالسازی با پشتیبانی تماس بگیر: /support"),
      mainMenuKeyboard()
    );
    return;
  }

  await bindPhone(env, phone, userId);
  user.profile.phone = phone;
  user.moderation.phoneDuplicate = false;

  user.state.flow = "onb_experience";
  await saveUser(env, user);

  const kbd = {
    keyboard: [
      [{ text: "مبتدی" }, { text: "متوسط" }, { text: "حرفه‌ای" }],
      [{ text: "⬅️ منو" }]
    ],
    resize_keyboard: true,
    is_persistent: true
  };
  await tgSendMessage(env, chatId, "عالی! سطح تجربه‌ات چیه؟", kbd);
}
async function handleOnboardingInput(env, cfg, chatId, userId, user, text) {
  const t = String(text || "").trim();

  if (t === "⬅️ منو" || t === "/menu") {
    user.state.flow = "idle";
    await saveUser(env, user);
    await tgSendMessage(env, chatId, welcomeText(env), mainMenuKeyboard());
    return;
  }

  if (user.state.flow === "onb_contact") {
    await tgSendMessage(env, chatId, "لطفاً از دکمه زیر شماره‌ات را Share Contact کن 👇", contactKeyboard());
    return;
  }

  if (user.state.flow === "onb_name") {
    user.profile.name = trunc(t, 50);
    user.state.flow = "onb_contact";
    await saveUser(env, user);
    await tgSendMessage(env, chatId, "حالا شماره‌ات را ارسال کن (Share Contact) 👇", contactKeyboard());
    return;
  }

  if (user.state.flow === "onb_experience") {
    if (!["مبتدی", "متوسط", "حرفه‌ای"].includes(t)) {
      await tgSendMessage(env, chatId, "یکی از گزینه‌ها را انتخاب کن: مبتدی / متوسط / حرفه‌ای", backToMenuKeyboard());
      return;
    }
    user.profile.experience = t;
    user.state.flow = "onb_market";
    await saveUser(env, user);
    await tgSendMessage(env, chatId, "کدام بازار را بیشتر دوست داری؟", marketsKeyboard());
    return;
  }

  if (user.state.flow === "onb_market") {
    const m = String(t).toUpperCase();
    if (!["CRYPTO", "FOREX", "METALS", "STOCKS"].includes(m)) {
      await tgSendMessage(env, chatId, "یکی از بازارها را انتخاب کن: CRYPTO / FOREX / METALS / STOCKS", marketsKeyboard());
      return;
    }
    user.profile.favoriteMarket = m;
    user.state.flow = "onb_tf";
    await saveUser(env, user);
    const kbd = { keyboard: [[{ text: "H1" }, { text: "H4" }, { text: "D1" }], [{ text: "M15" }, { text: "M30" }], [{ text: "⬅️ منو" }]], resize_keyboard: true, is_persistent: true };
    await tgSendMessage(env, chatId, "تایم‌فریم پیش‌فرض را انتخاب کن:", kbd);
    return;
  }

  if (user.state.flow === "onb_tf") {
    const tf = String(t).toUpperCase();
    if (!["H1", "H4", "D1", "M15", "M30"].includes(tf)) {
      await tgSendMessage(env, chatId, "TF نامعتبر. گزینه‌ها: M15/M30/H1/H4/D1", backToMenuKeyboard());
      return;
    }
    user.settings.tf = tf;
    user.state.flow = "onb_risk";
    await saveUser(env, user);
    const kbd = { keyboard: [[{ text: "کم" }, { text: "متوسط" }, { text: "زیاد" }], [{ text: "⬅️ منو" }]], resize_keyboard: true, is_persistent: true };
    await tgSendMessage(env, chatId, "سطح ریسک را انتخاب کن:", kbd);
    return;
  }

  if (user.state.flow === "onb_risk") {
    if (!["کم", "متوسط", "زیاد"].includes(t)) {
      await tgSendMessage(env, chatId, "ریسک نامعتبر. کم / متوسط / زیاد", backToMenuKeyboard());
      return;
    }
    user.settings.risk = t;
    user.settings.news = cfg.news.enabledDefault && cfg.features.newsEnabled;
    user.settings.style = "GENERAL";

    user.profile.onboardingDone = true;
    user.state.flow = "idle";

    // Award referral now that phone is unique and onboarding complete
    if (user.referral?.referredBy) {
      const r = await tryAwardReferral(env, cfg, user, userId);
      if (!r.ok && r.reason === "phone_used") {
        await tgSendMessage(env, chatId, "رفرال به دلیل تکراری بودن شماره تأیید نشد.", mainMenuKeyboard());
      } else if (r.ok) {
        await tgSendMessage(env, chatId, "🎉 رفرال شما با موفقیت ثبت شد.", mainMenuKeyboard());
        await tgSendMessage(env, r.inviterId, `🎁 دعوت موفق جدید! +${cfg.points.perInvite} امتیاز`, mainMenuKeyboard());
      }
    }

    await saveUser(env, user);
    await tgSendMessage(env, chatId, welcomeText(env), mainMenuKeyboard());
    return;
  }

  user.state.flow = "idle";
  await saveUser(env, user);
  await tgSendMessage(env, chatId, welcomeText(env), mainMenuKeyboard());
}

// Settings wizard
async function handleSettingsWizard(env, cfg, chatId, userId, user, text) {
  const t = String(text || "").trim();

  if (t === "⬅️ منو") {
    user.state.flow = "idle";
    await saveUser(env, user);
    await tgSendMessage(env, chatId, "منوی اصلی:", mainMenuKeyboard());
    return;
  }

  if (t.startsWith("⏱")) {
    user.state.flow = "set_tf";
    await saveUser(env, user);
    const kbd = { keyboard: [[{ text: "M15" }, { text: "M30" }, { text: "H1" }], [{ text: "H4" }, { text: "D1" }], [{ text: "⬅️ منو" }]], resize_keyboard: true, is_persistent: true };
    await tgSendMessage(env, chatId, "TF را انتخاب کن:", kbd);
    return;
  }

  if (t.startsWith("⚠️")) {
    user.state.flow = "set_risk";
    await saveUser(env, user);
    const kbd = { keyboard: [[{ text: "کم" }, { text: "متوسط" }, { text: "زیاد" }], [{ text: "⬅️ منو" }]], resize_keyboard: true, is_persistent: true };
    await tgSendMessage(env, chatId, "ریسک را انتخاب کن:", kbd);
    return;
  }

  if (t.startsWith("🧠 سبک") || t === "🧩 انتخاب سبک (لیست)") {
    user.state.flow = "set_style";
    await saveUser(env, user);
    const styles = availableStylesForUser(cfg, user);
    const rows = [];
    for (let i = 0; i < styles.length; i += 2) rows.push([{ text: styles[i] }, ...(styles[i + 1] ? [{ text: styles[i + 1] }] : [])]);
    rows.push([{ text: "⬅️ منو" }]);
    await tgSendMessage(env, chatId, "یکی از سبک‌ها را انتخاب کن:", { keyboard: rows, resize_keyboard: true, is_persistent: true });
    return;
  }

  if (t.startsWith("📰")) {
    user.settings.news = !user.settings.news;
    await saveUser(env, user);
    await tgSendMessage(env, chatId, `News اکنون: ${user.settings.news ? "روشن ✅" : "خاموش ❌"}`, settingsKeyboard(cfg, user));
    return;
  }

  if (user.state.flow === "set_tf") {
    const tf = String(t).toUpperCase();
    if (!["M15", "M30", "H1", "H4", "D1"].includes(tf)) {
      await tgSendMessage(env, chatId, "TF نامعتبر. گزینه‌ها: M15/M30/H1/H4/D1", backToMenuKeyboard());
      return;
    }
    user.settings.tf = tf;
    user.state.flow = "settings_menu";
    await saveUser(env, user);
    await tgSendMessage(env, chatId, "✅ TF ذخیره شد.", settingsKeyboard(cfg, user));
    return;
  }

  if (user.state.flow === "set_risk") {
    if (!["کم", "متوسط", "زیاد"].includes(t)) {
      await tgSendMessage(env, chatId, "ریسک نامعتبر. کم/متوسط/زیاد", backToMenuKeyboard());
      return;
    }
    user.settings.risk = t;
    user.state.flow = "settings_menu";
    await saveUser(env, user);
    await tgSendMessage(env, chatId, "✅ ریسک ذخیره شد.", settingsKeyboard(cfg, user));
    return;
  }

  if (user.state.flow === "set_style") {
    const style = String(t).toUpperCase();
    const allowed = availableStylesForUser(cfg, user);
    if (!allowed.includes(style)) {
      await tgSendMessage(env, chatId, "سبک نامعتبر یا هنوز فعال نیست.", backToMenuKeyboard());
      return;
    }
    user.settings.style = style;
    user.state.flow = "settings_menu";
    await saveUser(env, user);
    await tgSendMessage(env, chatId, `✅ سبک ذخیره شد: ${styleLabel(cfg, style)}`, settingsKeyboard(cfg, user));
    return;
  }

  await tgSendMessage(env, chatId, "برای تنظیمات از گزینه‌های کیبورد استفاده کن.", settingsKeyboard(cfg, user));
}

// Signals flow
async function startSignalsFlow(env, cfg, chatId, userId, user) {
  user.state.flow = "sig_market";
  user.state.data = {};
  await saveUser(env, user);
  await tgSendMessage(env, chatId, "بازار را انتخاب کن:", marketsKeyboard());
}
async function handleSignalsFlow(env, cfg, chatId, userId, user, text) {
  const t = String(text || "").trim();
  if (t === "⬅️ منو") {
    user.state.flow = "idle";
    await saveUser(env, user);
    await tgSendMessage(env, chatId, "منوی اصلی:", mainMenuKeyboard());
    return;
  }

  if (user.state.flow === "sig_market") {
    const m = t.toUpperCase();
    if (!["CRYPTO", "FOREX", "METALS", "STOCKS"].includes(m)) {
      await tgSendMessage(env, chatId, "یکی از بازارها را انتخاب کن.", marketsKeyboard());
      return;
    }
    user.state.data.market = m;
    user.state.flow = "sig_symbol";
    await saveUser(env, user);
    await tgSendMessage(env, chatId, `بازار انتخاب شد: ${m}\nحالا نماد را انتخاب کن:`, symbolsKeyboard(m));
    return;
  }

  if (user.state.flow === "sig_symbol") {
    if (t === "🔎 نماد دلخواه (تایپ کن)") {
      user.state.flow = "sig_custom_symbol";
      await saveUser(env, user);
      await tgSendMessage(env, chatId, "نماد دلخواه را تایپ کن (مثلاً BTCUSDT یا EURUSD یا AAPL):", backToMenuKeyboard());
      return;
    }
    const symbol = normalizeSymbolInput(t);
    if (!symbol) {
      await tgSendMessage(env, chatId, "نماد نامعتبر. دوباره انتخاب/تایپ کن.", symbolsKeyboard(user.state.data.market));
      return;
    }
    user.state.flow = "idle";
    await saveUser(env, user);
    await runSignalsAndSend(env, cfg, chatId, userId, user, user.state.data.market, symbol);
    return;
  }

  if (user.state.flow === "sig_custom_symbol") {
    const symbol = normalizeSymbolInput(t);
    if (!symbol) {
      await tgSendMessage(env, chatId, "نماد نامعتبر. دوباره تایپ کن یا ⬅️ منو.", backToMenuKeyboard());
      return;
    }
    const market = user.state.data.market || user.profile.favoriteMarket || "CRYPTO";
    user.state.flow = "idle";
    await saveUser(env, user);
    await runSignalsAndSend(env, cfg, chatId, userId, user, market, symbol);
    return;
  }

  await tgSendMessage(env, chatId, ensureBackHint("برای شروع تحلیل: /signals"), mainMenuKeyboard());
}

async function runSignalsAndSend(env, cfg, chatId, userId, user, market, symbol) {
  // Gate: onboarding required (except staff), and duplicate phone blocks
  if (!isAdminId(env, userId)) {
    if (user.moderation.phoneDuplicate) {
      await tgSendMessage(env, chatId, ensureBackHint("⛔️ شماره شما قبلاً ثبت شده و امکان استفاده از خدمات تحلیل وجود ندارد.\nلطفاً /support ارسال کن."), mainMenuKeyboard());
      return;
    }
    if (!user.profile.onboardingDone) {
      await tgSendMessage(env, chatId, "قبل از استفاده، onboarding را کامل کن.", mainMenuKeyboard());
      await startOnboarding(env, cfg, chatId, userId, user);
      return;
    }
  }

  const view = computeQuotaView(env, cfg, user, userId);
  if (!canConsumeQuota(view)) {
    const msg =
      "⛔️ سهمیه شما تمام شده است.\n\n" +
      `روزانه: ${quotaBar(view.dailyUsed, view.dailyLimit)}\n` +
      (view.monthlyLimit !== null ? `ماهانه: ${quotaBar(view.monthlyUsed, view.monthlyLimit)}\n` : "") +
      "\nبرای افزایش سهمیه، اشتراک تهیه کن: /buy";
    await tgSendMessage(env, chatId, ensureBackHint(msg), mainMenuKeyboard());
    return;
  }

  // Rate limit analyze
  const rl = await rateLimitAllow(env, cfg, "analyze", userId, cfg.security.rlAnalyzePerMin);
  if (!rl.ok) {
    await tgSendMessage(env, chatId, ensureBackHint("⏳ درخواست‌های تحلیل زیاد است. یک دقیقه بعد دوباره تلاش کن."), mainMenuKeyboard());
    return;
  }

  await tgSendChatAction(env, chatId, "typing");

  const prog = await tgSendMessage(env, chatId, `📈 شروع تحلیل ${symbol} (${market})...\n\n1/3 دریافت دیتا`, mainMenuKeyboard());
  const messageId = prog?.result?.message_id;

  try {
    // 1/3 data
    const candles = await getCandlesWithFallback(env, cfg, market, symbol, user.settings.tf);

    if (messageId) await tgEditMessageText(env, chatId, messageId, `📈 تحلیل ${symbol} (${market})\n\n✅ 1/3 دریافت دیتا\n2/3 تحلیل`);

    // 2/3 analysis
    await tgSendChatAction(env, chatId, "typing");

    const snap = snapshotFromCandles(candles);

    let newsBundle = null;
    if (user.settings.news && cfg.features.newsEnabled) {
      newsBundle = await getNewsBundle(env, cfg, market, symbol);

      // send separate news summary
      const newsMsg = `📰 خلاصه خبرهای مرتبط (${symbol})\n\n${newsBundle.summary_fa}`;
      await tgSendMessage(env, chatId, trunc(newsMsg, 3800), mainMenuKeyboard());
    }

    const prompt = buildAnalysisPrompt(cfg, user, market, symbol, user.settings.tf, snap, newsBundle);
    const ai = await callAI(env, cfg, "analysis", [{ role: "user", content: prompt }], 20000);

    let analysisText = "";
    let zones = [];
    if (ai.ok) {
      analysisText = String(ai.text || "");
      let zonesObj = extractLastJsonObject(analysisText);
      let val = validateZones(zonesObj);
      if (!val.ok) {
        const repaired = await repairZonesJsonOnce(env, cfg, analysisText);
        val = validateZones(repaired);
      }
      zones = val.ok ? val.zones : [];
      if (zonesObj) {
        const idx = analysisText.lastIndexOf("{");
        if (idx > 0) analysisText = analysisText.slice(0, idx).trim();
      }
    } else {
      analysisText = "❌ AI در دسترس نیست یا خطا داد.\n" + (ai.error || "");
      zones = [];
    }

    if (messageId) await tgEditMessageText(env, chatId, messageId, `📈 تحلیل ${symbol} (${market})\n\n✅ 1/3 دریافت دیتا\n✅ 2/3 تحلیل\n3/3 رسم چارت`);

    // 3/3 chart
    await tgSendChatAction(env, chatId, "upload_photo");

    const chartUrl = cfg.features.chartEnabled ? buildChartUrl(cfg, symbol, user.settings.tf, candles, zones) : "";

    // consume quota and store stats
    consumeQuota(user, view);
    user.stats.analysisCount = safeParseInt(user.stats.analysisCount, 0) + 1;
    user.stats.lastAnalysisAt = nowMs();
    await saveUser(env, user);
    await metricInc(env, "analyses", 1);

    const caption =
      `📌 ${symbol} (${market}) | TF: ${user.settings.tf} | Risk: ${user.settings.risk}\n\n` +
      trunc(analysisText || "", 1100) +
      (zones && zones.length ? `\n\n✅ Zones: ${zones.length}` : `\n\n⚠️ Zones یافت نشد (چارت بدون زون).`);

    if (chartUrl) await tgSendPhoto(env, chatId, chartUrl, caption);
    else await tgSendMessage(env, chatId, caption, mainMenuKeyboard());

    if (messageId) await tgEditMessageText(env, chatId, messageId, `✅ آماده شد.\n\nبرای تحلیل جدید: /signals`);
  } catch (e) {
    console.error("runSignalsAndSend error", e);
    if (messageId) {
      await tgEditMessageText(env, chatId, messageId, ensureBackHint("❌ خطا در دریافت دیتا/تحلیل. لطفاً دوباره تلاش کن."));
    } else {
      await tgSendMessage(env, chatId, ensureBackHint("❌ خطا. لطفاً دوباره تلاش کن."), mainMenuKeyboard());
    }
  }
}

// ========== Telegram commands handler ==========
async function handleLevelFlow(env, cfg, chatId, userId, user, text) {
  if (text === "/menu" || text === "⬅️ منو") {
    user.state.flow = "idle";
    await saveUser(env, user);
    await tgSendMessage(env, chatId, "منوی اصلی:", mainMenuKeyboard());
    return;
  }

  const idx = safeParseInt(user.state.data?.idx, 0);
  const answers = user.state.data?.answers || {};
  const q = LEVEL_QUESTIONS[idx];
  if (q) answers[q.id] = text;

  const nextIdx = idx + 1;
  if (nextIdx < LEVEL_QUESTIONS.length) {
    user.state.data = { idx: nextIdx, answers };
    await saveUser(env, user);
    await tgSendMessage(env, chatId, LEVEL_QUESTIONS[nextIdx].q, backToMenuKeyboard());
    return;
  }

  user.state.flow = "idle";
  user.state.data = {};
  await saveUser(env, user);

  await tgSendChatAction(env, chatId, "typing");

  const r = await evaluateLevelWithAI(env, cfg, answers);
  if (!r.ok) {
    await tgSendMessage(env, chatId, ensureBackHint("❌ خطا در تعیین سطح. لطفاً دوباره /level"), mainMenuKeyboard());
    return;
  }

  // Apply settings suggested
  const s = r.result.settings;
  user.settings.tf = ["M15", "M30", "H1", "H4", "D1"].includes(s.tf) ? s.tf : user.settings.tf;
  user.settings.risk = ["کم", "متوسط", "زیاد"].includes(s.risk) ? s.risk : user.settings.risk;
  // style: only if enabled and allowed
  const allowed = availableStylesForUser(cfg, user);
  user.settings.style = allowed.includes(s.style) ? s.style : user.settings.style;
  user.settings.news = !!s.news;

  await saveUser(env, user);

  const msg =
    `🧠 نتیجه تعیین سطح\n\n` +
    `سطح: ${r.result.level}\n` +
    `خلاصه: ${r.result.summary_fa}\n\n` +
    `پیشنهاد بازار: ${r.result.recommended_market}\n` +
    `تنظیمات پیشنهادی اعمال شد ✅\n` +
    `TF=${user.settings.tf} | Risk=${user.settings.risk} | Style=${styleLabel(cfg, user.settings.style)} | News=${user.settings.news ? "ON" : "OFF"}\n\n` +
    `اگر نیاز به «تعیین سطح مجدد» یا «تغییر تنظیمات» داری، از دکمه‌های زیر استفاده کن.\n`;

  await tgSendMessage(env, chatId, msg, mainMenuKeyboard(), { reply_markup: levelResultInline() });
}

async function handleMessage(env, cfg, chatId, userId, user, text, msg) {
  let t = String(text || "").trim();
  const mapped = mapButtonToCommand(t);
  if (mapped) t = mapped;

  // Basic webhook rate limit per user
  const rl = await rateLimitAllow(env, cfg, "webhook", userId, cfg.security.rlWebhookPerMin);
  if (!rl.ok) {
    // silently ignore heavy spam
    return;
  }

  // Ban gate
  if (isBanned(user)) {
    await tgSendMessage(env, chatId, `⛔️ شما مسدود هستید.\nتا: ${new Date(user.moderation.bannedUntil).toISOString()}\nدلیل: ${user.moderation.banReason}\n/support`, mainMenuKeyboard());
    return;
  }

  // long ops typing
  const longOps = ["/signals", "/level", "/customprompt", "/buy", "/pay", "/tx", "/profile"];
  if (longOps.some((c) => t.startsWith(c))) await tgSendChatAction(env, chatId, "typing");

  // Contact message for onboarding
  if (msg?.contact && user.state.flow === "onb_contact") {
    await handleContact(env, cfg, chatId, userId, user, msg.contact);
    return;
  }

  // Flow handlers
  if (user.state.flow.startsWith("onb_")) {
    await handleOnboardingInput(env, cfg, chatId, userId, user, t);
    return;
  }
  if (user.state.flow.startsWith("sig_")) {
    await handleSignalsFlow(env, cfg, chatId, userId, user, t);
    return;
  }
  if (user.state.flow.startsWith("settings") || user.state.flow.startsWith("set_")) {
    await handleSettingsWizard(env, cfg, chatId, userId, user, t);
    return;
  }
  if (user.state.flow === "await_txid") {
    const txid = t.replace(/^\/tx\s*/i, "").trim();
    const r = await registerTx(env, cfg, userId, txid);
    if (!r.ok) {
      await tgSendMessage(env, chatId, r.error, mainMenuKeyboard());
      return;
    }
    user.state.flow = "idle";
    await saveUser(env, user);
    await tgSendMessage(env, chatId, "✅ TXID ثبت شد و در انتظار تایید است.", mainMenuKeyboard());
    await notifyStaff(env, `💳 پرداخت جدید (pending)\nUser: ${userId}\nTXID: ${txid}`, {
      inline_keyboard: [[{ text: "✅ Approve", callback_data: `pay:approve:${txid}` }, { text: "❌ Reject", callback_data: `pay:reject:${txid}` }]]
    });
    return;
  }
  if (user.state.flow === "level_q") {
    await handleLevelFlow(env, cfg, chatId, userId, user, t);
    return;
  }
  if (user.state.flow === "ticket_write") {
    user.state.flow = "idle";
    await saveUser(env, user);
    const ticket = await createTicket(env, userId, t);
    await tgSendMessage(env, chatId, "✅ پیام شما ثبت شد. پشتیبانی پاسخ می‌دهد.", mainMenuKeyboard());
    await notifyStaff(env, `🆘 تیکت جدید\nTicket: ${ticket.id}\nUser: ${userId}\nText: ${trunc(t, 700)}`);
    return;
  }
  if (user.state.flow === "customprompt_wait_text") {
    const strategyText = t;
    user.state.flow = "idle";
    await saveUser(env, user);

    const gen = await generateCustomPrompt(env, cfg, strategyText);
    user.customPrompt.requestedAt = nowMs();
    user.customPrompt.deliverAt = nowMs() + 2 * 3600 * 1000;
    user.customPrompt.prompt = gen.ok ? gen.prompt : "";
    user.customPrompt.ready = false; // required: only after delivery
    await saveUser(env, user);

    if (gen.ok) {
      // queue task
      const taskKey = kTask(user.customPrompt.deliverAt, "customprompt", userId, randomToken(4));
      await kvPutJson(env, taskKey, { userId: String(userId), kind: "customprompt" }, { expirationTtl: 24 * 3600 });
      await tgSendMessage(env, chatId, "✅ Prompt اختصاصی ساخته شد و 2 ساعت بعد برایت ارسال می‌شود. تا قبل از ارسال، سبک Custom فعال نیست.", mainMenuKeyboard());
    } else {
      await tgSendMessage(env, chatId, "❌ ساخت Prompt با خطا مواجه شد. دوباره تلاش کن.", mainMenuKeyboard());
    }
    return;
  }

  // Commands
  if (t === "/start" || t.startsWith("/start ")) {
    // parse referral code param
    const parts = t.split(/\s+/);
    if (parts.length >= 2) {
      const code = parts[1].trim();
      const inviterId = await resolveReferralOwnerId(env, code);
      if (inviterId && inviterId !== String(userId) && !user.referral.referredBy) {
        user.referral.referredBy = inviterId;
        await saveUser(env, user);
      }
    }

    await tgSendMessage(env, chatId, welcomeText(env), mainMenuKeyboard());
    if (!user.profile.onboardingDone && !user.moderation.phoneDuplicate) await startOnboarding(env, cfg, chatId, userId, user);
    if (user.moderation.phoneDuplicate) {
      await tgSendMessage(env, chatId, ensureBackHint("⚠️ این شماره قبلاً ثبت شده است. برای فعالسازی /support"), mainMenuKeyboard());
    }
    return;
  }

  if (t === "/menu") {
    await tgSendMessage(env, chatId, "منوی اصلی:", mainMenuKeyboard());
    if (!user.profile.onboardingDone && !user.moderation.phoneDuplicate) await startOnboarding(env, cfg, chatId, userId, user);
    return;
  }

  if (t === "/signals") {
    if (user.moderation.phoneDuplicate) {
      await tgSendMessage(env, chatId, ensureBackHint("⛔️ به دلیل تکراری بودن شماره، امکان تحلیل فعال نیست. /support"), mainMenuKeyboard());
      return;
    }
    if (!user.profile.onboardingDone && !isAdminId(env, userId)) {
      await tgSendMessage(env, chatId, "قبل از استفاده، onboarding را کامل کن.", mainMenuKeyboard());
      await startOnboarding(env, cfg, chatId, userId, user);
      return;
    }
    await startSignalsFlow(env, cfg, chatId, userId, user);
    return;
  }

  if (t === "/settings") {
    if (!user.profile.onboardingDone && !isAdminId(env, userId) && !user.moderation.phoneDuplicate) {
      await tgSendMessage(env, chatId, "قبل از تنظیمات، onboarding را کامل کن.", mainMenuKeyboard());
      await startOnboarding(env, cfg, chatId, userId, user);
      return;
    }
    user.state.flow = "settings_menu";
    await saveUser(env, user);
    await tgSendMessage(env, chatId, "تنظیمات:", settingsKeyboard(cfg, user));
    return;
  }

  if (t === "/profile") {
    const view = computeQuotaView(env, cfg, user, userId);
    const isSub = user.subscription?.active && user.subscription.until > nowMs();
    const until = isSub ? new Date(user.subscription.until).toISOString().slice(0, 10) : "-";
    const msg2 =
      `👤 پروفایل\n\n` +
      `نام: ${user.profile.name || "-"}\n` +
      `شماره: ${user.profile.phone || "-"}\n` +
      `تجربه: ${user.profile.experience || "-"}\n` +
      `بازار علاقه‌مند: ${user.profile.favoriteMarket || "-"}\n\n` +
      `🎛 تنظیمات: TF=${user.settings.tf} | Risk=${user.settings.risk} | Style=${styleLabel(cfg, user.settings.style)} | News=${user.settings.news ? "ON" : "OFF"}\n\n` +
      `💳 اشتراک: ${isSub ? "فعال ✅" : "غیرفعال"} | تا: ${until}\n` +
      `⚡ سهمیه روزانه: ${quotaBar(view.dailyUsed, view.dailyLimit)}\n` +
      (view.monthlyLimit !== null ? `📅 سهمیه ماهانه: ${quotaBar(view.monthlyUsed, view.monthlyLimit)}\n` : "") +
      `\n🎁 امتیاز: ${user.referral.points || 0}\n` +
      `🤝 دعوت‌های موفق: ${user.referral.successfulInvites || 0}\n` +
      `💸 کمیسیون: ${user.referral.commissionPct || 0}%\n`;
    await tgSendMessage(env, chatId, msg2, mainMenuKeyboard());
    return;
  }

  if (t === "/wallet") {
    const w = await publicWallet(env, cfg);
    await tgSendMessage(env, chatId, `💰 آدرس ولت عمومی USDT (BEP20):\n${w || "❗️ تنظیم نشده"}`, mainMenuKeyboard());
    return;
  }

  if (t === "/buy" || t === "/pay") {
    const w = await publicWallet(env, cfg);
    const msg3 =
      `💳 خرید اشتراک (فقط USDT روی شبکه BEP20)\n\n` +
      `قیمت: ${cfg.subscription.priceUSDT} USDT\n` +
      `مدت: ${cfg.subscription.durationDays} روز\n\n` +
      `آدرس ولت:\n${w || "❗️ تنظیم نشده"}\n\n` +
      "بعد از پرداخت، TXID را ارسال کن:\n" +
      "/tx <TXID>\n";
    await tgSendMessage(env, chatId, msg3, mainMenuKeyboard(), { reply_markup: buyInlineKeyboard() });
    return;
  }

  if (t.startsWith("/tx")) {
    const parts = t.split(/\s+/);
    if (parts.length < 2) {
      user.state.flow = "await_txid";
      await saveUser(env, user);
      await tgSendMessage(env, chatId, "TXID را ارسال کن (فقط هگز).", mainMenuKeyboard());
      return;
    }
    const txid = parts[1];
    const r = await registerTx(env, cfg, userId, txid);
    if (!r.ok) {
      await tgSendMessage(env, chatId, r.error, mainMenuKeyboard());
      return;
    }
    await tgSendMessage(env, chatId, "✅ TXID ثبت شد و در انتظار تایید است.", mainMenuKeyboard());
    await notifyStaff(env, `💳 پرداخت جدید (pending)\nUser: ${userId}\nTXID: ${txid}`, {
      inline_keyboard: [[{ text: "✅ Approve", callback_data: `pay:approve:${txid}` }, { text: "❌ Reject", callback_data: `pay:reject:${txid}` }]]
    });
    return;
  }

  if (t === "/payments") {
    if (!isAdminId(env, userId)) {
      await tgSendMessage(env, chatId, "⛔️ دسترسی ندارید.", mainMenuKeyboard());
      return;
    }
    const r = await listPaymentsByStatus(env, "pending", 20, "");
    const items = r.items || [];
    if (!items.length) {
      await tgSendMessage(env, chatId, "پرداخت pending نداریم.", mainMenuKeyboard());
      return;
    }
    let out = "💳 پرداخت‌های Pending:\n\n";
    for (const p of items.slice(0, 15)) {
      out += `- TXID: ${p.txid}\n  User: ${p.userId}\n  Price: ${p.priceUSDT} | Days: ${p.durationDays}\n\n`;
    }
    await tgSendMessage(env, chatId, trunc(out, 3900), mainMenuKeyboard());
    return;
  }

  if (t.startsWith("/approve")) {
    if (!isAdminId(env, userId)) return tgSendMessage(env, chatId, "⛔️ دسترسی ندارید.", mainMenuKeyboard());
    const txid = t.split(/\s+/)[1] || "";
    const r = await approvePayment(env, cfg, txid, userId);
    if (!r.ok) return tgSendMessage(env, chatId, r.error, mainMenuKeyboard());
    await tgSendMessage(env, chatId, "✅ تایید شد.", mainMenuKeyboard());
    await tgSendMessage(env, r.user.id, `✅ پرداخت تایید شد. اشتراک شما فعال شد.\nتا: ${new Date(r.user.subscription.until).toISOString().slice(0, 10)}`, mainMenuKeyboard());
    return;
  }

  if (t.startsWith("/reject")) {
    if (!isAdminId(env, userId)) return tgSendMessage(env, chatId, "⛔️ دسترسی ندارید.", mainMenuKeyboard());
    const parts = t.split(/\s+/);
    const txid = parts[1] || "";
    const reason = parts.slice(2).join(" ");
    const r = await rejectPayment(env, txid, userId, reason);
    if (!r.ok) return tgSendMessage(env, chatId, r.error, mainMenuKeyboard());
    await tgSendMessage(env, chatId, "❌ رد شد.", mainMenuKeyboard());
    await tgSendMessage(env, r.payment.userId, `❌ پرداخت رد شد.\nTXID: ${txid}\n${reason ? "دلیل: " + reason : ""}`, mainMenuKeyboard());
    return;
  }

  if (t.startsWith("/setwallet")) {
    if (!isAdminId(env, userId)) return tgSendMessage(env, chatId, "⛔️ دسترسی ندارید.", mainMenuKeyboard());
    const addr = t.split(/\s+/)[1] || "";
    const old = (await publicWallet(env, cfg)) || "";

    // Owner-only recommended, but allowed for admin too per spec; we still ALARM owners.
    cfg.walletPublic = String(addr).trim();
    await saveConfig(env, userId, cfg, "setwallet");

    await tgSendMessage(env, chatId, `✅ ولت تغییر کرد.\nOld: ${old}\nNew: ${cfg.walletPublic}`, mainMenuKeyboard());
    await notifyOwners(env, `🚨 هشدار تغییر ولت عمومی توسط ${userId}\nOld: ${old}\nNew: ${cfg.walletPublic}`);
    await notifyStaff(env, `ℹ️ ولت عمومی تغییر کرد.\nBy: ${userId}\nNew: ${cfg.walletPublic}`);

    return;
  }

  if (t.startsWith("/setfreelimit")) {
    if (!isAdminId(env, userId)) return tgSendMessage(env, chatId, "⛔️ دسترسی ندارید.", mainMenuKeyboard());
    const n = safeParseInt(t.split(/\s+/)[1], cfg.limits.freeDaily);
    cfg.limits.freeDaily = Math.max(1, n);
    await saveConfig(env, userId, cfg, "setfreelimit");
    await tgSendMessage(env, chatId, `✅ free daily limit = ${cfg.limits.freeDaily}`, mainMenuKeyboard());
    return;
  }

  if (t.startsWith("/setsublimit")) {
    if (!isAdminId(env, userId)) return tgSendMessage(env, chatId, "⛔️ دسترسی ندارید.", mainMenuKeyboard());
    const n = safeParseInt(t.split(/\s+/)[1], cfg.subscription.dailyLimit);
    cfg.subscription.dailyLimit = Math.max(1, n);
    await saveConfig(env, userId, cfg, "setsublimit");
    await tgSendMessage(env, chatId, `✅ sub daily limit = ${cfg.subscription.dailyLimit}`, mainMenuKeyboard());
    return;
  }

  if (t.startsWith("/setprice")) {
    if (!isAdminId(env, userId)) return tgSendMessage(env, chatId, "⛔️ دسترسی ندارید.", mainMenuKeyboard());
    const n = safeParseFloat(t.split(/\s+/)[1], cfg.subscription.priceUSDT);
    cfg.subscription.priceUSDT = Math.max(0.1, n);
    await saveConfig(env, userId, cfg, "setprice");
    await tgSendMessage(env, chatId, `✅ price = ${cfg.subscription.priceUSDT} USDT`, mainMenuKeyboard());
    return;
  }

  if (t.startsWith("/setduration")) {
    if (!isAdminId(env, userId)) return tgSendMessage(env, chatId, "⛔️ دسترسی ندارید.", mainMenuKeyboard());
    const n = safeParseInt(t.split(/\s+/)[1], cfg.subscription.durationDays);
    cfg.subscription.durationDays = Math.max(1, n);
    await saveConfig(env, userId, cfg, "setduration");
    await tgSendMessage(env, chatId, `✅ duration = ${cfg.subscription.durationDays} days`, mainMenuKeyboard());
    return;
  }

  if (t === "/ref") {
    const code = user.referral.code;
    const msg4 =
      `🎁 رفرال\n\nکد شما: ${code}\n\n` +
      `برای دعوت:\n` +
      `1) به دوستت بگو: /start ${code}\n` +
      `2) حتما Share Contact کند (شماره باید جدید باشد)\n\n` +
      `دعوت موفق: ${user.referral.successfulInvites || 0}\n` +
      `امتیاز: ${user.referral.points || 0}\n` +
      `کمیسیون فعلی: ${user.referral.commissionPct || 0}% (tiered)\n\n` +
      `تبدیل امتیاز به اشتراک رایگان: /redeem\n`;
    await tgSendMessage(env, chatId, msg4, mainMenuKeyboard());
    return;
  }

  if (t === "/redeem") {
    const points = safeParseInt(user.referral.points, 0);
    const need = cfg.points.redeemFreeSub;
    if (points < need) {
      await tgSendMessage(env, chatId, `امتیاز کافی نیست.\nنیاز: ${need}\nفعلی: ${points}`, mainMenuKeyboard());
      return;
    }
    // Redeem all possible multiples
    const times = Math.floor(points / need);
    user.referral.points = points - times * need;

    const addMs = cfg.subscription.durationDays * 24 * 3600 * 1000 * times;
    const base = user.subscription?.active && user.subscription.until > nowMs() ? user.subscription.until : nowMs();
    user.subscription.active = true;
    user.subscription.until = base + addMs;
    user.subscription.plan = "SUB";
    user.subscription.dailyLimit = cfg.subscription.dailyLimit;

    await saveUser(env, user);

    await tgSendMessage(env, chatId, `✅ تبدیل انجام شد.\nتعداد: ${times}\nاشتراک فعال شد.\nتا: ${new Date(user.subscription.until).toISOString().slice(0, 10)}`, mainMenuKeyboard());
    return;
  }

  if (t === "/level") {
    if (!user.profile.onboardingDone && !isAdminId(env, userId) && !user.moderation.phoneDuplicate) {
      await tgSendMessage(env, chatId, "قبل از تعیین سطح، onboarding را کامل کن.", mainMenuKeyboard());
      await startOnboarding(env, cfg, chatId, userId, user);
      return;
    }
    user.state.flow = "level_q";
    user.state.data = { idx: 0, answers: {} };
    await saveUser(env, user);
    await tgSendMessage(env, chatId, "🧠 آزمون تعیین سطح شروع شد.\n\n" + LEVEL_QUESTIONS[0].q, backToMenuKeyboard());
    return;
  }

  if (t === "/customprompt") {
    if (!user.profile.onboardingDone && !isAdminId(env, userId) && !user.moderation.phoneDuplicate) {
      await tgSendMessage(env, chatId, "قبل از /customprompt، onboarding را کامل کن.", mainMenuKeyboard());
      await startOnboarding(env, cfg, chatId, userId, user);
      return;
    }
    user.state.flow = "customprompt_wait_text";
    await saveUser(env, user);
    await tgSendMessage(env, chatId, "🧩 استراتژی/روش اختصاصی‌ات را بنویس.\n(پس از آماده شدن، 2 ساعت بعد خودکار ارسال می‌شود)", backToMenuKeyboard());
    return;
  }

  if (t === "/support") {
    user.state.flow = "ticket_write";
    await saveUser(env, user);
    await tgSendMessage(env, chatId, "🆘 پیام پشتیبانی را بنویس. (برای برگشت /menu)", backToMenuKeyboard());
    return;
  }

  if (t === "/education") {
    const msg5 =
      "📚 آموزش\n\n" +
      "1) از /signals برای انتخاب Market و Symbol استفاده کن.\n" +
      "2) در /settings تایم‌فریم، ریسک، سبک و News را تنظیم کن.\n" +
      "3) برای خرید اشتراک /buy و سپس /tx <TXID>.\n" +
      "4) رفرال: /ref\n" +
      "5) تعیین سطح: /level\n" +
      "6) Custom Prompt: /customprompt\n";
    await tgSendMessage(env, chatId, msg5, mainMenuKeyboard());
    return;
  }

  if (t === "/miniapp") {
    const url = "/";
    const msg6 = `🧩 Mini App آماده است:\n${url}\n\n(برای باز شدن داخل تلگرام، از دکمه زیر استفاده کن)`;
    await tgSendMessage(env, chatId, msg6, mainMenuKeyboard(), { reply_markup: { inline_keyboard: [[{ text: "Open MiniApp", web_app: { url } }]] } });
    return;
  }

  // Owner-only tools
  if (t === "/setwebhook") {
    if (!isOwnerId(env, userId)) return tgSendMessage(env, chatId, "⛔️ فقط Owner.", mainMenuKeyboard());
    const wh = String(env.WEBHOOK_URL || "").trim();
    const secret = String(env.TELEGRAM_SECRET_TOKEN || "").trim();
    if (!wh) return tgSendMessage(env, chatId, "WEBHOOK_URL تنظیم نشده.", mainMenuKeyboard());
    const r = await tgCall(env, "setWebhook", { url: wh, secret_token: secret || undefined, drop_pending_updates: false });
    await tgSendMessage(env, chatId, `setWebhook نتیجه:\n${JSON.stringify(r)}`, mainMenuKeyboard());
    return;
  }
  if (t === "/getwebhook") {
    if (!isOwnerId(env, userId)) return tgSendMessage(env, chatId, "⛔️ فقط Owner.", mainMenuKeyboard());
    const r = await tgCall(env, "getWebhookInfo", {});
    await tgSendMessage(env, chatId, `getWebhookInfo:\n${JSON.stringify(r)}`, mainMenuKeyboard());
    return;
  }

  if (t.startsWith("/ban")) {
    if (!isOwnerId(env, userId)) return tgSendMessage(env, chatId, "⛔️ فقط Owner.", mainMenuKeyboard());
    const parts = t.split(/\s+/);
    const target = parts[1] || "";
    const hours = clamp(safeParseInt(parts[2], 24), 1, 24 * 365);
    const reason = parts.slice(3).join(" ") || "ban";
    const u = await kvGetJson(env, kUser(target));
    if (!u) return tgSendMessage(env, chatId, "کاربر پیدا نشد.", mainMenuKeyboard());
    u.moderation = u.moderation || {};
    u.moderation.bannedUntil = nowMs() + hours * 3600 * 1000;
    u.moderation.banReason = reason.slice(0, 200);
    await saveUser(env, u);
    await auditLog(env, userId, "user_ban_cmd", null, null, { target, hours, reason });
    await tgSendMessage(env, chatId, "✅ انجام شد.", mainMenuKeyboard());
    await tgSendMessage(env, target, `⛔️ شما مسدود شده‌اید.\nمدت: ${hours} ساعت\nدلیل: ${reason}\n/support`, mainMenuKeyboard());
    return;
  }
  if (t.startsWith("/unban")) {
    if (!isOwnerId(env, userId)) return tgSendMessage(env, chatId, "⛔️ فقط Owner.", mainMenuKeyboard());
    const target = t.split(/\s+/)[1] || "";
    const u = await kvGetJson(env, kUser(target));
    if (!u) return tgSendMessage(env, chatId, "کاربر پیدا نشد.", mainMenuKeyboard());
    u.moderation = u.moderation || {};
    u.moderation.bannedUntil = 0;
    u.moderation.banReason = "";
    await saveUser(env, u);
    await auditLog(env, userId, "user_unban_cmd", null, null, { target });
    await tgSendMessage(env, chatId, "✅ انجام شد.", mainMenuKeyboard());
    await tgSendMessage(env, target, "✅ محدودیت شما برداشته شد.", mainMenuKeyboard());
    return;
  }

  // Unknown
  await tgSendMessage(env, chatId, ensureBackHint("دستور/پیام نامعتبر بود. از منو استفاده کن."), mainMenuKeyboard());
}

// ========== Callback queries ==========
async function handleCallback(env, cfg, cq) {
  const id = cq.id;
  const data = String(cq.data || "");
  const chatId = cq.message?.chat?.id;
  const fromId = cq.from?.id;
  if (!chatId || !fromId) return;

  const user = await ensureUser(env, fromId);

  if (data === "buy:txid") {
    user.state.flow = "await_txid";
    await saveUser(env, user);
    await tgAnswerCallback(env, id, "TXID را ارسال کن.", false);
    await tgSendMessage(env, chatId, "TXID را بفرست:\n/tx <TXID>", mainMenuKeyboard());
    return;
  }

  if (data === "buy:wallet") {
    const w = await publicWallet(env, cfg);
    await tgAnswerCallback(env, id, "ولت ارسال شد.", false);
    await tgSendMessage(env, chatId, `💰 ولت عمومی:\n${w || "❗️ تنظیم نشده"}`, mainMenuKeyboard());
    return;
  }

  if (data === "buy:help") {
    await tgAnswerCallback(env, id, "راهنما", false);
    await tgSendMessage(env, chatId, "راهنما:\n1) پرداخت USDT(BEP20)\n2) دریافت TXID\n3) ارسال /tx <TXID>\n4) منتظر تایید", mainMenuKeyboard());
    return;
  }

  if (data.startsWith("pay:approve:")) {
    if (!isAdminId(env, fromId)) {
      await tgAnswerCallback(env, id, "دسترسی ندارید.", true);
      return;
    }
    const txid = data.split(":")[2] || "";
    const r = await approvePayment(env, cfg, txid, fromId);
    if (!r.ok) {
      await tgAnswerCallback(env, id, r.error, true);
      return;
    }
    await tgAnswerCallback(env, id, "Approved ✅", false);
    await tgSendMessage(env, chatId, "✅ تایید شد.", mainMenuKeyboard());
    await tgSendMessage(env, r.user.id, `✅ پرداخت تایید شد. اشتراک فعال شد.\nتا: ${new Date(r.user.subscription.until).toISOString().slice(0, 10)}`, mainMenuKeyboard());
    return;
  }

  if (data.startsWith("pay:reject:")) {
    if (!isAdminId(env, fromId)) {
      await tgAnswerCallback(env, id, "دسترسی ندارید.", true);
      return;
    }
    const txid = data.split(":")[2] || "";
    const r = await rejectPayment(env, txid, fromId, "Rejected by staff");
    if (!r.ok) {
      await tgAnswerCallback(env, id, r.error, true);
      return;
    }
    await tgAnswerCallback(env, id, "Rejected ❌", false);
    await tgSendMessage(env, chatId, "❌ رد شد.", mainMenuKeyboard());
    await tgSendMessage(env, r.payment.userId, `❌ پرداخت رد شد.\nTXID: ${txid}`, mainMenuKeyboard());
    return;
  }

  if (data === "level:req:retry") {
    await tgAnswerCallback(env, id, "ارسال شد.", false);
    await notifyStaff(env, `🧠 درخواست تعیین سطح مجدد\nUser: ${fromId}`);
    await tgSendMessage(env, chatId, "✅ درخواست شما برای Owner/Admin ارسال شد.", mainMenuKeyboard());
    return;
  }
  if (data === "level:req:settings") {
    await tgAnswerCallback(env, id, "ارسال شد.", false);
    await notifyStaff(env, `⚙️ درخواست تغییر تنظیمات\nUser: ${fromId}`);
    await tgSendMessage(env, chatId, "✅ درخواست شما برای Owner/Admin ارسال شد.", mainMenuKeyboard());
    return;
  }

  await tgAnswerCallback(env, id, "OK", false);
}

// ========== Telegram webhook processing ==========
async function processUpdate(env, cfg, update) {
  try {
    if (update && typeof update.update_id === "number") {
      const dup = await isDuplicateUpdate(env, update.update_id);
      if (dup) return;
    }

    if (update.callback_query) {
      await handleCallback(env, cfg, update.callback_query);
      return;
    }

    const msg = update.message || update.edited_message;
    if (!msg) return;

    const chatId = msg.chat?.id;
    const fromId = msg.from?.id;
    if (!chatId || !fromId) return;

    const user = await ensureUser(env, fromId);

    // Handle contact
    if (msg.contact && user.state.flow === "onb_contact") {
      await handleContact(env, cfg, chatId, fromId, user, msg.contact);
      return;
    }

    if (msg.text) {
      await handleMessage(env, cfg, chatId, fromId, user, msg.text, msg);
      return;
    }
  } catch (e) {
    console.error("processUpdate error", e);
  }
}

async function handleTelegramWebhook(request, env, ctx) {
  if (!isTelegramSecretValid(request, env)) return new Response("forbidden", { status: 403 });

  let update = null;
  try {
    update = await request.json();
  } catch {
    // Always respond ok
    return textResponse("ok");
  }

  const cfg = await loadConfig(env);

  // MUST respond immediately; do heavy work in waitUntil
  ctx.waitUntil(
    (async () => {
      try {
        await processUpdate(env, cfg, update);
      } catch (e) {
        console.error("waitUntil update error", e);
      }
    })()
  );

  return textResponse("ok");
}

// ========== Cron processing ==========
async function processTasks(env, cfg) {
  const prefix = kTaskIdx();
  const r = await kvList(env, prefix, 60, undefined);
  const keys = r.keys || [];
  const now = nowMs();
  for (const k of keys) {
    const name = k.name;
    const parts = name.split(":");
    // marketiq:task:TS:kind:userId:rand
    const tsStr = parts[2] || "";
    const kind = parts[3] || "";
    const userId = parts[4] || "";
    const ts = safeParseInt(tsStr, 0);
    if (!ts || ts > now) continue;

    try {
      const u = await ensureUser(env, userId);
      if (kind === "customprompt") {
        // Activate custom prompt now and send it
        const promptText = u.customPrompt?.prompt || "";
        if (promptText) {
          u.customPrompt.ready = true;
          await saveUser(env, u);
          await tgSendMessage(env, userId, `🧩 Custom Prompt شما آماده است ✅\n\n${promptText}\n\nاکنون می‌توانید در تنظیمات سبک Custom را انتخاب کنید.`, mainMenuKeyboard());
          await metricInc(env, "customPromptDelivered", 1);
        } else {
          await tgSendMessage(env, userId, "❌ Custom Prompt آماده نشد. لطفاً دوباره /customprompt", mainMenuKeyboard());
        }
      }
    } catch (e) {
      console.error("task process error", e);
    }

    await kvDel(env, name);
  }
}

async function processCron(env) {
  const cfg = await loadConfig(env);

  // housekeeping
  await expireOldPendingPayments(env, cfg);
  await ticketSlaReminder(env);

  // tasks queue
  await processTasks(env, cfg);

  // broadcast jobs
  if (cfg.features.broadcastEnabled) await processBroadcastJobs(env, cfg);
}

// ========== Router ==========
async function router(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;

  // Basic CORS preflight (optional)
  if (request.method === "OPTIONS") {
    return new Response("", {
      status: 204,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET,POST,OPTIONS",
        "access-control-allow-headers": "content-type,x-telegram-init-data,x-init-data,authorization"
      }
    });
  }

  // Health
  if (path === "/health") {
    return jsonResponse({ ok: true, name: botName(env), version: VERSION, routes: ["/telegram", "/", "/admin", "/api/*", "/api/admin/*"] });
  }

  // Telegram webhook
  if (path === "/telegram" && request.method === "POST") {
    return await handleTelegramWebhook(request, env, ctx);
  }

  // Miniapp route must be ROOT
  if (path === "/" && request.method === "GET") {
    return htmlResponse(miniAppHtml());
  }
  // Alias /miniapp -> /
  if (path === "/miniapp") {
    return new Response("", { status: 302, headers: { location: "/" } });
  }

  // Admin panel
  if (path === "/admin" && request.method === "GET") {
    return htmlResponse(adminHtml());
  }

  // APIs
  const cfg = await loadConfig(env);

  if (path.startsWith("/api/admin/")) return await handleAdminApi(request, env, cfg);
  if (path.startsWith("/api/")) return await handleMiniAppApi(request, env, cfg);

  // robots/fav
  if (path === "/robots.txt") return textResponse("User-agent: *\nDisallow: /");
  if (path === "/favicon.ico") return new Response("", { status: 204 });

  return new Response("Not Found", { status: 404 });
}

// ========== Worker entry ==========
export default {
  async fetch(request, env, ctx) {
    try {
      return await router(request, env, ctx);
    } catch (e) {
      console.error("fetch top error", e);
      // Fail-safe: never crash
      return textResponse("ok", 200);
    }
  },

  async scheduled(event, env, ctx) {
    try {
      ctx.waitUntil(processCron(env));
    } catch (e) {
      console.error("scheduled error", e);
    }
  }
};