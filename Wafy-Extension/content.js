// ============================================================
//  WAFinity Content Script — runs on every page
//  Intercepts: form submits, link clicks, URL params, XHR/fetch
// ============================================================

(function () {
  // Don't run on extension pages or chrome:// pages
  if (!window.location.href.startsWith("http")) return;

  let blockingEnabled = true;

  // Sync settings from storage
  chrome.storage.local.get(["blockingEnabled"], (d) => {
    if (typeof d.blockingEnabled === "boolean") blockingEnabled = d.blockingEnabled;
  });
  chrome.storage.onChanged.addListener((changes) => {
    if (changes.blockingEnabled) blockingEnabled = changes.blockingEnabled.newValue;
  });

  // ── Ask background to check a payload ──────────────────
  function checkPayload(payload, context) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { type: "CHECK_PAYLOAD", payload, context },
        (resp) => resolve(resp || { safe: true })
      );
    });
  }

  // ── Show in-page threat banner ──────────────────────────
  function showThreatBanner(result, blockedWhat) {
    // Remove existing
    const old = document.getElementById("wafinity-banner");
    if (old) old.remove();

    const banner = document.createElement("div");
    banner.id = "wafinity-banner";
    banner.setAttribute("style", `
      position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
      background: linear-gradient(135deg, #0d0d0d 0%, #1a0505 100%);
      border-bottom: 2px solid #ff2d55;
      color: #fff; font-family: 'Segoe UI', monospace; font-size: 13px;
      padding: 0; box-shadow: 0 4px 30px rgba(255,45,85,0.5);
      animation: wafSlideDown 0.3s ease;
    `);

    const sev = result.severity || "HIGH";
    const sevColor = { CRITICAL: "#ff2d55", HIGH: "#ff6b2b", MEDIUM: "#ffd60a", LOW: "#00ff88" }[sev] || "#ff2d55";

    banner.innerHTML = `
      <style>
        @keyframes wafSlideDown { from { transform: translateY(-100%); opacity:0; } to { transform: translateY(0); opacity:1; } }
        @keyframes wafPulse { 0%,100%{opacity:1} 50%{opacity:0.5} }
        #wafinity-banner * { box-sizing: border-box; }
        #wafinity-banner .waf-main { display:flex; align-items:center; gap:12px; padding:10px 16px; }
        #wafinity-banner .waf-icon { font-size:22px; animation: wafPulse 1s infinite; flex-shrink:0; }
        #wafinity-banner .waf-info { flex:1; min-width:0; }
        #wafinity-banner .waf-title { font-weight:700; font-size:13px; color:${sevColor}; letter-spacing:1px; }
        #wafinity-banner .waf-detail { font-size:11px; color:#aaa; margin-top:2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        #wafinity-banner .waf-badges { display:flex; gap:6px; margin-top:4px; flex-wrap:wrap; }
        #wafinity-banner .waf-badge { padding:1px 8px; border-radius:10px; font-size:10px; font-weight:600; letter-spacing:0.5px; }
        #wafinity-banner .badge-sev { background:${sevColor}22; color:${sevColor}; border:1px solid ${sevColor}44; }
        #wafinity-banner .badge-type { background:rgba(0,245,212,0.1); color:#00f5d4; border:1px solid rgba(0,245,212,0.3); }
        #wafinity-banner .badge-score { background:rgba(168,85,247,0.1); color:#a855f7; border:1px solid rgba(168,85,247,0.3); }
        #wafinity-banner .waf-actions { display:flex; gap:8px; flex-shrink:0; }
        #wafinity-banner .waf-btn { padding:5px 12px; border-radius:6px; font-size:11px; font-weight:600; cursor:pointer; border:none; letter-spacing:0.5px; transition:opacity 0.2s; }
        #wafinity-banner .waf-btn:hover { opacity:0.8; }
        #wafinity-banner .btn-block { background:#ff2d55; color:#fff; }
        #wafinity-banner .btn-allow { background:rgba(255,255,255,0.1); color:#aaa; border:1px solid rgba(255,255,255,0.2) !important; }
        #wafinity-banner .btn-dismiss { background:transparent; color:#555; font-size:16px; padding:4px 8px; }
        #wafinity-banner .waf-explain { padding:0 16px 8px; font-size:11px; color:#888; border-top:1px solid rgba(255,45,85,0.15); padding-top:6px; }
      </style>
      <div class="waf-main">
        <div class="waf-icon">🚨</div>
        <div class="waf-info">
          <div class="waf-title">⛔ WAFinity BLOCKED — ${result.attack_type || "Threat"} Detected</div>
          <div class="waf-detail">${blockedWhat}</div>
          <div class="waf-badges">
            <span class="waf-badge badge-sev">${sev}</span>
            <span class="waf-badge badge-type">${result.attack_type || "Unknown"}</span>
            <span class="waf-badge badge-score">Score: ${result.threat_score ?? "?"}/100</span>
          </div>
        </div>
        <div class="waf-actions">
          <button class="waf-btn btn-allow" id="waf-allow-btn">Allow Anyway</button>
          <button class="waf-btn btn-dismiss" id="waf-dismiss-btn">✕</button>
        </div>
      </div>
      ${result.explanation ? `<div class="waf-explain">💡 ${result.explanation}</div>` : ""}
    `;

    document.body.insertBefore(banner, document.body.firstChild);
    setTimeout(() => { if (banner.parentNode) banner.remove(); }, 8000);

    return new Promise((resolve) => {
      document.getElementById("waf-allow-btn").addEventListener("click", () => {
        banner.remove(); resolve("allow");
      });
      document.getElementById("waf-dismiss-btn").addEventListener("click", () => {
        banner.remove(); resolve("dismiss");
      });
    });
  }

  // ── Intercept FORM SUBMISSIONS ──────────────────────────
  document.addEventListener("submit", async (e) => {
    if (!blockingEnabled) return;
    const form = e.target;
    const inputs = [...form.querySelectorAll("input, textarea, select")];
    const values = inputs.map(i => i.value).filter(v => v && v.trim()).join(" ");
    if (!values) return;

    e.preventDefault();
    e.stopImmediatePropagation();

    const result = await checkPayload(values, "form-submit");
    if (!result.safe) {
      const action = await showThreatBanner(result, `Form input blocked: "${values.substring(0, 80)}"`);
      if (action === "allow") form.submit();
    } else {
      form.submit();
    }
  }, true);

  // ── Intercept LINK CLICKS with suspicious URLs ──────────
  document.addEventListener("click", async (e) => {
    if (!blockingEnabled) return;
    const anchor = e.target.closest("a[href]");
    if (!anchor) return;
    const href = anchor.href;
    if (!href || href.startsWith("javascript:") || href.startsWith("#")) return;

    // Only check URLs that look suspicious
    if (!/[<>'";=\(\)\[\]{}\\%]/.test(href) && !/\?.*=/.test(href)) return;

    e.preventDefault();
    e.stopImmediatePropagation();

    const result = await checkPayload(href, "link-click");
    if (!result.safe) {
      const action = await showThreatBanner(result, `Blocked URL: ${href.substring(0, 100)}`);
      if (action === "allow") window.location.href = href;
    } else {
      window.location.href = href;
    }
  }, true);

  // ── Intercept FETCH / XHR (monkey-patch) ───────────────
  // Only flag suspicious payloads sent via fetch/XHR
  const _fetch = window.fetch;
  window.fetch = async function (input, init) {
    if (!blockingEnabled) return _fetch.apply(this, arguments);
    try {
      const body = init && init.body ? String(init.body) : "";
      if (body && body.length > 2) {
        const result = await checkPayload(body, "fetch-body");
        if (!result.safe) {
          showThreatBanner(result, `Fetch request body blocked`);
          // Let it through anyway since blocking fetch breaks too many sites
        }
      }
    } catch (_) {}
    return _fetch.apply(this, arguments);
  };

  // ── Scan current page URL params on load ───────────────
  window.addEventListener("DOMContentLoaded", async () => {
    if (!blockingEnabled) return;
    const search = window.location.search;
    if (!search || search.length < 3) return;
    const result = await checkPayload(window.location.href, "url-params");
    if (!result.safe) {
      showThreatBanner(result, `Suspicious URL parameters detected: ${search.substring(0, 100)}`);
    }
  });

})();
