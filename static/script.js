const $ = (id) => document.getElementById(id);
const ARC_LEN = 173; // approx path length of the gauge arc
let currentId = null;
let batchResults = [];
let lastResult = null;

/* ---------- helpers ---------- */
function verdictClass(v) {
  if (v.includes("SCAM")) return "scam";
  if (v.includes("SUSPICIOUS")) return "suspicious";
  return "safe";
}

// Build elements with textContent only -> user input can never inject HTML (XSS-safe)
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  Object.entries(props).forEach(([k, v]) => {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v);
  });
  children.forEach((c) => c && node.appendChild(c));
  return node;
}

function tag(verdict) {
  return el("span", { class: "tag " + verdictClass(verdict), text: verdict });
}

function short(s, n = 70) {
  return s.length > n ? s.slice(0, n) + "..." : s;
}

async function api(path, body, method = "POST") {
  const opts = { method };
  if (body instanceof FormData) opts.body = body;
  else if (body) {
    opts.headers = { "Content-Type": "application/json" };
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Something went wrong.");
  return data;
}

async function withBusy(btn, label, fn) {
  const old = btn.textContent;
  btn.disabled = true;
  btn.textContent = label;
  try {
    await fn();
  } catch (e) {
    alert(e.message === "Failed to fetch" ? "Could not reach the server. Is app.py running?" : e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = old;
  }
}

/* ---------- theme & tabs ---------- */
const THEMES = [["matrix", "🟢"], ["cyber", "🟣"], ["redteam", "🔴"]];
function setTheme(name) {
  const t = THEMES.find((x) => x[0] === name) || THEMES[0];
  document.documentElement.dataset.theme = t[0];
  $("themeBtn").textContent = t[1];
  try { localStorage.setItem("theme", t[0]); } catch (e) {}
}
$("themeBtn").addEventListener("click", () => {
  const i = THEMES.findIndex((x) => x[0] === document.documentElement.dataset.theme);
  const next = THEMES[(i + 1) % THEMES.length][0];
  setTheme(next);
  log(`[*] theme switched -> ${next}`, "info");
});
try { setTheme(localStorage.getItem("theme") || "matrix"); } catch (e) { setTheme("matrix"); }

document.querySelectorAll(".tab").forEach((t) =>
  t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach((x) => x.classList.remove("active"));
    t.classList.add("active");
    $(t.dataset.tab).classList.add("active");
  }));

/* ---------- message analysis ---------- */
function urlCard(u) {
  const card = el("div", { class: "url-card" },
    el("div", { class: "top" }, el("code", { text: u.url }), el("span", {}, tag(u.verdict), el("b", { text: "  " + u.risk + "%" }))));
  if (u.flags.length) {
    const ul = el("ul");
    u.flags.forEach((f) => ul.appendChild(el("li", { text: f })));
    card.appendChild(ul);
  } else {
    card.appendChild(el("ul", {}, el("li", { text: "No suspicious traits found in this link." })));
  }
  return card;
}

const IOC_LABELS = { emails: "email", upi_ids: "upi", phones: "phone", ips: "ip", crypto_wallets: "wallet" };
function renderIocs(iocs) {
  const chips = [];
  Object.entries(IOC_LABELS).forEach(([key, label]) => {
    (iocs[key] || []).forEach((item) => {
      const value = typeof item === "string" ? item : item.value;
      const bad = typeof item !== "string" && item.flags.length > 0;
      chips.push(el("span", { class: "ioc" + (bad ? " bad" : ""), title: bad ? item.flags.join(" | ") : "" },
        el("b", { text: label }), document.createTextNode(value)));
    });
  });
  $("iocBox").style.display = chips.length ? "block" : "none";
  $("iocList").replaceChildren(...chips);
}

function renderResult(data) {
  lastResult = data;
  currentId = data.id;
  renderIocs(data.iocs || {});
  $("resultPanel").style.display = "block";
  const cls = verdictClass(data.verdict);
  $("verdictBadge").textContent = data.verdict;
  $("verdictBadge").className = "verdict-badge " + cls;
  $("riskValue").textContent = data.risk;
  $("gaugeArc").setAttribute("stroke-dasharray", `${(ARC_LEN * data.risk) / 100} ${ARC_LEN}`);
  const gc = cls === "scam" ? "var(--danger)" : cls === "suspicious" ? "var(--warn)" : "var(--safe)";
  $("gaugeArc").style.stroke = gc;
  $("gaugeArc").parentNode.style.color = gc;
  $("mlBar").style.width = data.ml + "%";
  $("ruleBar").style.width = data.rule + "%";
  $("mlVal").textContent = data.ml + "%";
  $("ruleVal").textContent = data.rule + "%";

  $("adviceBox").className = "advice " + data.level;
  $("adviceBox").textContent = "💡 " + data.advice;

  const terms = data.top_terms || [];
  $("termsBox").style.display = terms.length ? "block" : "none";
  $("termsList").replaceChildren(...terms.map((t) => el("span", { class: "term", text: t.term })));

  const urls = data.url_analysis || [];
  $("urlsBox").style.display = urls.length ? "block" : "none";
  $("urlsList").replaceChildren(...urls.map(urlCard));

  const reasons = data.reasons.length ? data.reasons : ["No red flags found. Message looks normal."];
  $("reasonsList").replaceChildren(...reasons.map((r) => el("li", { text: r })));

  $("fbMsg").textContent = "";
  $("feedbackBox").style.display = data.id ? "flex" : "none";
  $("resultPanel").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

$("analyzeBtn").addEventListener("click", () => {
  const text = $("msgInput").value.trim();
  if (!text) return;
  withBusy($("analyzeBtn"), "Scanning...", async () => {
    log(`[*] payload received (${text.length} bytes)`, "info");
    log("[*] tokenizing + extracting IOCs...");
    const data = await api("/api/analyze", { text });
    await sleep(350);
    log(`[*] ML score ${data.ml}% | rule engine ${data.rule}%`);
    log(`[${data.level === "low" ? "+" : "!"}] VERDICT: ${data.verdict} (risk ${data.risk}%)`,
        data.level === "high" ? "bad" : data.level === "medium" ? "warn" : "ok");
    renderResult(data);
    refresh();
  });
});
$("clearBtn").addEventListener("click", () => {
  $("msgInput").value = "";
  $("charCount").textContent = 0;
  $("resultPanel").style.display = "none";
});
$("msgInput").addEventListener("input", () => ($("charCount").textContent = $("msgInput").value.length));
$("msgInput").addEventListener("keydown", (e) => {
  if (e.ctrlKey && e.key === "Enter") $("analyzeBtn").click();
});
document.querySelectorAll(".chip").forEach((chip) =>
  chip.addEventListener("click", () => {
    $("msgInput").value = chip.dataset.text;
    $("charCount").textContent = chip.dataset.text.length;
    $("analyzeBtn").click();
  }));
$("charCount").textContent = $("msgInput").value.length;

async function sendFeedback(correct) {
  try {
    await api("/api/feedback", { id: currentId, correct });
    $("fbMsg").textContent = "Thanks for the feedback!";
    refresh();
  } catch (e) {
    $("fbMsg").textContent = e.message;
  }
}
$("fbYes").addEventListener("click", () => sendFeedback(true));
$("fbNo").addEventListener("click", () => sendFeedback(false));

/* ---------- URL scanner ---------- */
$("urlBtn").addEventListener("click", () => {
  const url = $("urlInput").value.trim();
  if (!url) return;
  withBusy($("urlBtn"), "Scanning...", async () => {
    log(`[*] scanning url: ${short(url, 50)}`, "info");
    const r = await api("/api/url", { url });
    log(`[${r.level === "low" ? "+" : "!"}] URL verdict: ${r.verdict} (${r.risk}%)`, r.level === "high" ? "bad" : r.level === "medium" ? "warn" : "ok");
    const box = $("urlResult");
    box.style.display = "block";
    box.replaceChildren(urlCard(r), el("div", { class: "advice " + r.level, text: "💡 " + r.advice }));
    refresh();
  });
});
$("urlInput").addEventListener("keydown", (e) => { if (e.key === "Enter") $("urlBtn").click(); });

/* ---------- batch ---------- */
$("batchFile").addEventListener("change", (e) => {
  const f = e.target.files[0];
  if (!f) return;
  withBusy($("batchBtn"), "Analyzing...", async () => {
    const fd = new FormData();
    fd.append("file", f);
    renderBatch(await api("/api/batch", fd));
    refresh();
  });
  e.target.value = "";
});
$("batchBtn").addEventListener("click", () => {
  const messages = $("batchInput").value.split("\n").map((s) => s.trim()).filter(Boolean);
  if (!messages.length) return;
  withBusy($("batchBtn"), "Analyzing...", async () => {
    log(`[*] batch scan: ${messages.length} messages`, "info");
    renderBatch(await api("/api/batch", { messages }));
    log("[+] batch complete", "ok");
    refresh();
  });
});

function renderBatch(data) {
  batchResults = data.results;
  const s = data.summary;
  $("batchSummary").style.display = "flex";
  $("batchSummary").replaceChildren(
    el("span", { class: "tag safe", text: `Safe: ${s["SAFE"]}` }),
    el("span", { class: "tag suspicious", text: `Suspicious: ${s["SUSPICIOUS"]}` }),
    el("span", { class: "tag scam", text: `Scam: ${s["PHISHING / SCAM"]}` }),
    el("span", { class: "tag", text: `Total: ${data.count}` }));
  $("batchTable").style.display = "table";
  $("batchDl").style.display = "inline-block";
  $("batchBody").replaceChildren(...data.results.map((r) => {
    const tr = el("tr", { class: "clickable" },
      el("td", { text: short(r.text) }), el("td", {}, tag(r.verdict)), el("td", { text: r.risk + "%" }));
    tr.addEventListener("click", () => renderResult({ ...r, id: null }));
    return tr;
  }));
}

function csvCell(v) {
  let s = String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // block spreadsheet formula injection
  return '"' + s.replace(/"/g, '""') + '"';
}
$("batchDl").addEventListener("click", () => {
  const rows = [["text", "verdict", "risk_percent", "reasons"]].concat(
    batchResults.map((r) => [r.text, r.verdict, r.risk, r.reasons.join(" | ")]));
  const blob = new Blob([rows.map((r) => r.map(csvCell).join(",")).join("\n")], { type: "text/csv" });
  const a = el("a", { href: URL.createObjectURL(blob), download: "batch_results.csv" });
  a.click();
  URL.revokeObjectURL(a.href);
});

/* ---------- history & stats ---------- */
async function loadHistory() {
  const items = await api("/api/history", null, "GET");
  if (!items.length) {
    $("historyBody").replaceChildren(el("tr", {}, el("td", { colspan: "4", class: "empty", text: "Nothing analyzed yet." })));
    return;
  }
  $("historyBody").replaceChildren(...items.map((item) => {
    const tr = el("tr", { class: "clickable", title: "Click to view details" },
      el("td", { text: item.kind }), el("td", { text: short(item.text) }),
      el("td", {}, tag(item.verdict)), el("td", { text: item.risk + "%" }));
    tr.addEventListener("click", () => {
      if (item.kind === "url") {
        $("urlInput").value = item.text;
        $("urlResult").style.display = "block";
        $("urlResult").replaceChildren(urlCard(item.result), el("div", { class: "advice " + item.result.level, text: "💡 " + item.result.advice }));
        document.querySelector('[data-tab="urlTab"]').click();
      } else {
        renderResult({ ...item.result, id: item.id });
      }
    });
    return tr;
  }));
}

async function loadStats() {
  const s = await api("/api/stats", null, "GET");
  const c = s.verdict_counts, total = s.checked_count || 0;
  const parts = [["d-safe", c["SAFE"]], ["d-sus", c["SUSPICIOUS"]], ["d-scam", c["PHISHING / SCAM"]]];
  $("distBar").replaceChildren(...(total
    ? parts.filter(([, n]) => n).map(([cls, n]) => {
        const d = el("div", { class: cls, text: n });
        d.style.width = (n / total) * 100 + "%";
        return d;
      })
    : [el("div", { text: "No checks yet" })]));
}

function refresh() { loadHistory(); loadStats(); }

$("clearHistBtn").addEventListener("click", async () => {
  if (!confirm("Delete all saved history?")) return;
  await api("/api/history", null, "DELETE");
  refresh();
});

refresh();


/* ================= hacker extras ================= */
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function log(msg, cls = "") {
  const box = $("console");
  box.appendChild(el("div", { class: cls, text: msg }));
  while (box.children.length > 7) box.removeChild(box.firstChild);
}

/* reports */
function download(name, text, type) {
  const a = el("a", { href: URL.createObjectURL(new Blob([text], { type })), download: name });
  a.click();
  URL.revokeObjectURL(a.href);
}
$("repJson").addEventListener("click", () => lastResult && download("threat_report.json", JSON.stringify(lastResult, null, 2), "application/json"));
$("repTxt").addEventListener("click", () => {
  if (!lastResult) return;
  const r = lastResult, L = [];
  L.push("PHISH//HUNTER THREAT REPORT  (by Satyam Kanojiya)", "=".repeat(52));
  L.push(`Verdict : ${r.verdict}`, `Risk    : ${r.risk}%  (AI ${r.ml}% | rules ${r.rule}%)`, "", "MESSAGE:", r.text || "(n/a)", "");
  L.push("REASONS:", ...(r.reasons.length ? r.reasons.map((x) => " - " + x) : [" - none"]), "");
  Object.entries(IOC_LABELS).forEach(([k, label]) => (r.iocs?.[k] || []).forEach((i) => L.push(`IOC ${label}: ${typeof i === "string" ? i : i.value}`)));
  L.push("", "ADVICE: " + r.advice);
  download("threat_report.txt", L.join("\n"), "text/plain");
});

/* matrix rain */
(function () {
  const c = $("rain"), ctx = c.getContext("2d");
  if (!ctx || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const chars = "アイウエオカキクケコサシスセソ0123456789ABCDEF<>/{}$#".split("");
  let cols, drops;
  function resize() {
    c.width = innerWidth; c.height = innerHeight;
    cols = Math.floor(c.width / 16);
    drops = Array.from({ length: cols }, () => Math.random() * -50);
  }
  addEventListener("resize", resize); resize();
  setInterval(() => {
    if (document.hidden) return;
    ctx.fillStyle = "rgba(0,0,0,.08)";
    ctx.fillRect(0, 0, c.width, c.height);
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--rain").trim() || "#00ff66";
    ctx.font = "15px monospace";
    drops.forEach((y, i) => {
      ctx.fillText(chars[Math.floor(Math.random() * chars.length)], i * 16, y * 16);
      drops[i] = y * 16 > c.height && Math.random() > 0.975 ? 0 : y + 1;
    });
  }, 55);
})();

/* boot sequence (once per session) */
(async function boot() {
  const box = $("boot"), out = $("bootText");
  let seen = false;
  try { seen = sessionStorage.getItem("booted") === "1"; } catch (e) {}
  const finish = () => {
    box.classList.add("hide");
    try { sessionStorage.setItem("booted", "1"); } catch (e) {}
    setTimeout(() => box.remove(), 700);
  };
  if (seen) { box.remove(); } else {
    let skip = false;
    box.addEventListener("click", () => (skip = true));
    const lines = [
      "PHISH//HUNTER v2.0  —  created by Satyam Kanojiya",
      "[ OK ] initializing neural core ............",
      "[ OK ] loading TF-IDF + Logistic Regression model",
      "[ OK ] arming rule engine (urls, otp, kyc, hinglish)",
      "[ OK ] typosquat & punycode detectors online",
      "[ OK ] IOC extractor online",
      "",
      "ACCESS GRANTED. Welcome, analyst.",
    ];
    for (const l of lines) {
      if (skip) break;
      out.textContent += l + "\n";
      await sleep(190);
    }
    await sleep(skip ? 0 : 350);
    finish();
  }
  log("[+] system online - all modules loaded", "ok");
  log("[*] paste a message / url and hit scan", "info");
})();
