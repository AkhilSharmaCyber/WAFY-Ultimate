// ============================================================
//  WAFinity Security Shield  —  background.js (MV3 Service Worker)
// ============================================================

const API = "http://127.0.0.1:5000";

let sessionStats = { checked: 0, threats: 0, backendOnline: false };

// ── Trusted domains — NEVER send to WAF ───────────────────
const TRUSTED_DOMAINS = [
  "google.com","googleapis.com","gstatic.com","googleusercontent.com",
  "googlevideo.com","youtube.com","ytimg.com","ggpht.com",
  "googletagmanager.com","doubleclick.net","googlesyndication.com",
  "accounts.google.com","fonts.gstatic.com","fonts.googleapis.com",
  "microsoft.com","msn.com","live.com","outlook.com","office.com",
  "microsoftonline.com","bing.com","azure.com","windows.net",
  "apple.com","icloud.com","mzstatic.com",
  "amazon.com","amazonaws.com","cloudfront.net",
  "facebook.com","instagram.com","fbcdn.net","whatsapp.com",
  "cloudflare.com","jsdelivr.net","unpkg.com","fastly.net",
  "openai.com","chatgpt.com","anthropic.com","claude.ai",
  "twitter.com","x.com","twimg.com",
  "linkedin.com","licdn.com",
  "reddit.com","redditmedia.com","redditstatic.com",
  "github.com","githubusercontent.com","githubassets.com",
  "stackoverflow.com","stackexchange.com",
  "wikipedia.org","wikimedia.org",
  "netflix.com","spotify.com","twitch.tv",
  "127.0.0.1","localhost",
];

function isTrustedDomain(urlStr) {
  try {
    const h = new URL(urlStr).hostname.toLowerCase();
    return TRUSTED_DOMAINS.some(d => h === d || h.endsWith("." + d));
  } catch { return false; }
}

// ── Backend health ─────────────────────────────────────────
async function checkBackendHealth() {
  try {
    const r = await fetch(`${API}/health`, { signal: AbortSignal.timeout(2000) });
    const ok = r.ok;
    if (ok !== sessionStats.backendOnline) {
      sessionStats.backendOnline = ok;
      chrome.storage.local.set({ backendOnline: ok });
    }
    return ok;
  } catch {
    if (sessionStats.backendOnline) {
      sessionStats.backendOnline = false;
      chrome.storage.local.set({ backendOnline: false });
    }
    return false;
  }
}

// ── Core analysis — called by content script messages ─────
async function analysePayload(payload, context) {
  if (!payload || payload.trim().length < 2) return { safe: true };

  // Skip trusted domains for URL context
  if ((context === "url-params" || context === "link-click") && isTrustedDomain(payload)) {
    return { safe: true };
  }

  sessionStats.checked++;
  try {
    const res = await fetch(`${API}/check_request`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_request: payload }),
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return { safe: true };
    const data = await res.json();
    sessionStats.backendOnline = true;

    if (data.status === "malicious" || data.status === "blocked") {
      // Avoid noise: AI_Anomaly needs high score
      if (data.attack_type === "AI_Anomaly" && (data.threat_score || 0) < 75) {
        chrome.storage.local.set({ checked: sessionStats.checked, backendOnline: true });
        return { safe: true };
      }

      sessionStats.threats++;
      const entry = {
        url: payload.substring(0, 200),
        attack_type: data.attack_type || "Unknown",
        severity: data.severity || "HIGH",
        threat_score: data.threat_score ?? 0,
        explanation: data.explanation || "",
        context: context || "unknown",
        time: new Date().toLocaleTimeString(),
        ts: Date.now(),
      };

      chrome.storage.local.get(["threatHistory"], (stored) => {
        const history = stored.threatHistory || [];
        history.unshift(entry);
        if (history.length > 50) history.splice(50);
        chrome.storage.local.set({
          threatHistory: history,
          lastThreat: entry,
          threats: sessionStats.threats,
          checked: sessionStats.checked,
          backendOnline: true,
        });
      });

      fireNotification(entry);
      return { safe: false, ...data };
    }

    chrome.storage.local.set({ checked: sessionStats.checked, backendOnline: true });
    return { safe: true };

  } catch {
    if (sessionStats.backendOnline) {
      sessionStats.backendOnline = false;
      chrome.storage.local.set({ backendOnline: false });
    }
    return { safe: true }; // Don't block if backend is down
  }
}

// ── Notifications ──────────────────────────────────────────
function fireNotification(entry) {
  const icons = { CRITICAL: "⛔", HIGH: "🚨", MEDIUM: "⚠️", LOW: "🔔" };
  const sevIcon = icons[entry.severity] || "🚨";
  chrome.notifications.create({
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: `${sevIcon} WAFinity — ${entry.severity} Threat BLOCKED`,
    message: `${entry.attack_type} detected & blocked!\n${entry.url.substring(0, 100)}`,
    priority: entry.severity === "CRITICAL" ? 2 : 1,
  });
}

// ── Message listener — from content.js ────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "CHECK_PAYLOAD") {
    analysePayload(msg.payload, msg.context).then(sendResponse);
    return true; // keep channel open for async
  }
  if (msg.type === "GET_STATS") {
    chrome.storage.local.get(
      ["checked", "threats", "threatHistory", "backendOnline"],
      sendResponse
    );
    return true;
  }
});

// ── Background URL scan (webRequest — passive scan) ───────
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const url = details.url;
    if (!url) return {};
    if (/^(chrome|about|data|blob|chrome-extension):/.test(url)) return {};
    if (isTrustedDomain(url)) return {};
    // Only scan URLs with query params or suspicious chars
    if (/[<>'";=]/.test(url) || /\?.*=/.test(url)) {
      analysePayload(url, "web-request");
    }
    return {};
  },
  { urls: ["<all_urls>"] }
);

// ── Poll live attacks from server every 5s ─────────────────
chrome.alarms.create("pollLive", { periodInMinutes: 1 / 12 });
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== "pollLive") return;
  try {
    const r = await fetch(`${API}/recent_attacks`, { signal: AbortSignal.timeout(3000) });
    if (!r.ok) return;
    const a = await r.json();
    if (Array.isArray(a)) chrome.storage.local.set({ liveAttacks: a.slice(0, 10) });
  } catch {}
  checkBackendHealth();
});

// ── Init ───────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    checked: 0, threats: 0,
    lastThreat: null, threatHistory: [],
    liveAttacks: [], backendOnline: false,
    blockingEnabled: true,
  });
  checkBackendHealth();
});

checkBackendHealth();
setInterval(checkBackendHealth, 10000);
