// =============================================
//  WAFinity Popup Script v2.1
// =============================================
const API = "http://127.0.0.1:5000";

// ── Tab switching ──────────────────────────
const TABS = [
  { btn: "tab-threats", panel: "panel-threats" },
  { btn: "tab-test",    panel: "panel-test"    },
  { btn: "tab-about",   panel: "panel-about"   },
];
TABS.forEach(({ btn, panel }) => {
  document.getElementById(btn).addEventListener("click", () => {
    TABS.forEach(t => {
      document.getElementById(t.btn).classList.remove("active");
      document.getElementById(t.panel).classList.remove("active");
    });
    document.getElementById(btn).classList.add("active");
    document.getElementById(panel).classList.add("active");
  });
});

// ── Blocking toggle ────────────────────────
const toggle = document.getElementById("blocking-toggle");
chrome.storage.local.get(["blockingEnabled"], (d) => {
  toggle.checked = d.blockingEnabled !== false;
});
toggle.addEventListener("change", () => {
  chrome.storage.local.set({ blockingEnabled: toggle.checked });
  const label = document.getElementById("status-label");
  if (!toggle.checked) {
    label.textContent = "paused";
    label.className = "offline";
  }
});

// ── Status ─────────────────────────────────
function setStatus(online) {
  const dot   = document.getElementById("status-dot");
  const label = document.getElementById("status-label");
  dot.className   = "pulse-dot " + (online ? "online" : "offline");
  label.className = online ? "online" : "offline";
  if (toggle.checked) label.textContent = online ? "protected" : "offline";
}

// ── Stats ──────────────────────────────────
function setStats(checked, threats) {
  document.getElementById("s-checked").textContent = checked || 0;
  document.getElementById("s-threats").textContent = threats || 0;
  document.getElementById("s-safe").textContent = Math.max(0, (checked || 0) - (threats || 0));
}

// ── Build threat card ──────────────────────
function buildThreatItem(t) {
  const sev = t.severity || "HIGH";
  const ctxIcons = {
    "form-submit": "📝",
    "link-click":  "🔗",
    "url-params":  "🌐",
    "web-request": "📡",
    "fetch-body":  "📤",
  };
  const ctxIcon = ctxIcons[t.context] || "🔍";

  const div = document.createElement("div");
  div.className = "threat-item " + sev;

  const top = document.createElement("div");
  top.className = "t-top";

  const typeSpan = document.createElement("span");
  typeSpan.className = "t-type";
  typeSpan.textContent = ctxIcon + " " + (t.attack_type || "Unknown");

  const sevSpan = document.createElement("span");
  sevSpan.className = "t-sev " + sev;
  sevSpan.textContent = sev;

  top.appendChild(typeSpan);
  top.appendChild(sevSpan);

  const urlDiv = document.createElement("div");
  urlDiv.className = "t-url";
  urlDiv.textContent = (t.url || "").substring(0, 140);

  const meta = document.createElement("div");
  meta.className = "t-meta";

  const score = document.createElement("span");
  score.className = "t-score";
  score.textContent = "Score: " + (t.threat_score ?? "?") + "/100";

  const time = document.createElement("span");
  time.className = "t-time";
  time.textContent = t.time || "";

  meta.appendChild(score);
  meta.appendChild(time);
  div.appendChild(top);
  div.appendChild(urlDiv);
  div.appendChild(meta);

  if (t.explanation) {
    const exp = document.createElement("div");
    exp.className = "t-explain";
    exp.textContent = "💡 " + t.explanation;
    div.appendChild(exp);
  }

  return div;
}

// ── Render feed ────────────────────────────
function renderFeed(history) {
  const feed = document.getElementById("feed");
  feed.innerHTML = "";
  if (!history || history.length === 0) {
    const state = document.createElement("div");
    state.className = "empty-state";
    const icon = document.createElement("span");
    icon.className = "empty-icon";
    icon.textContent = "🛡️";
    const text = document.createElement("div");
    text.className = "empty-text";
    text.textContent = "No threats blocked yet.\nWAFinity is watching your tab.";
    state.appendChild(icon);
    state.appendChild(text);
    feed.appendChild(state);
    return;
  }
  history.forEach(t => feed.appendChild(buildThreatItem(t)));
}

// ── Load from storage ─────────────────────
function loadFromStorage() {
  chrome.storage.local.get(
    ["checked", "threats", "threatHistory", "backendOnline"],
    (data) => {
      setStats(data.checked, data.threats);
      renderFeed(data.threatHistory || []);
      setStatus(!!data.backendOnline);
    }
  );
}
loadFromStorage();
chrome.storage.onChanged.addListener(() => loadFromStorage());

// ── Payload tester ────────────────────────
function showResult(className, text) {
  const result = document.getElementById("test-result");
  result.className = "result-card " + className;
  result.textContent = text;
  result.style.display = "block";
}

async function runTest() {
  const input = document.getElementById("test-input").value.trim();
  const btn   = document.getElementById("analyse-btn");
  if (!input) return;
  btn.disabled    = true;
  btn.textContent = "⏳ Analysing…";
  showResult("thinking", "Sending to WAFinity engine…");
  try {
    const res = await fetch(API + "/check_request", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_request: input }),
      signal: AbortSignal.timeout(5000),
    });
    const d = await res.json();
    if (d.status === "valid") {
      showResult("valid", "✅  SAFE\n\nNo threats detected. Request cleared.");
    } else if (d.status === "malicious") {
      showResult("malicious",
        "🚨  MALICIOUS — WOULD BE BLOCKED\n\n" +
        "Attack Type  :  " + d.attack_type + "\n" +
        "Severity     :  " + d.severity + "\n" +
        "Threat Score :  " + d.threat_score + "/100\n\n" +
        (d.explanation || ""));
    } else if (d.status === "blocked") {
      showResult("malicious", "⛔  BLOCKED\n\n" + d.message);
    } else if (d.status === "obfuscated") {
      showResult("obfuscated",
        "⚠️  OBFUSCATED PAYLOAD\n\nML verdict: " + d.ml_verdict + "\n" + (d.message || ""));
    } else {
      showResult("thinking", JSON.stringify(d, null, 2));
    }
  } catch (err) {
    showResult("error",
      "❌  Backend unreachable\n\n" +
      "Make sure python app.py is running\n" +
      "at http://127.0.0.1:5000\n\n" +
      "Error: " + err.message);
  } finally {
    btn.disabled    = false;
    btn.textContent = "▶ Analyse Payload";
  }
}

document.getElementById("test-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); runTest(); }
});
document.getElementById("analyse-btn").addEventListener("click", runTest);

// ── Footer ────────────────────────────────
document.getElementById("btn-dashboard").addEventListener("click", () => {
  chrome.tabs.create({ url: API + "/stats" });
});
document.getElementById("btn-clear").addEventListener("click", () => {
  chrome.storage.local.set({ threatHistory: [], threats: 0 }, loadFromStorage);
});
