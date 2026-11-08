(() => {
  const $ = (id) => document.getElementById(id);
  const el = (tag, text, cls) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; };
  let current = null;
  const call = async (path, body, key) => {
    const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json", ...(key ? { "X-API-Key": key } : {}) }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || r.statusText); return j;
  };
  $("f").addEventListener("submit", async (ev) => {
    ev.preventDefault(); $("go").disabled = true; $("status").textContent = "Analysing… (fetching the page, checking the certificate)"; $("result").hidden = true;
    try { current = await call("/api/analyze", { url: $("url").value, deep: $("deep").checked, authorized: $("auth").checked }); render(current); $("status").textContent = `Done in ${current.elapsed_s}s`; }
    catch (e) { $("status").textContent = "Error: " + e.message; } finally { $("go").disabled = false; }
  });
  function render(r) {
    $("result").hidden = false;
    $("verdictBox").className = "card verdict " + r.verdict;
    $("score").textContent = r.risk_score; $("label").textContent = r.label;
    $("sub").textContent = r.display_host + (r.final_url && r.final_url !== r.url ? "  →  " + r.final_url : "");
    $("notes").textContent = r.notes.join(" ");
    $("gradeBox").hidden = !r.security_posture; if (r.security_posture) $("grade").textContent = r.security_posture.grade;
    const fill = (ul, items, empty) => { ul.replaceChildren(); if (!items.length) ul.append(el("li", empty, "muted"));
      for (const s of items) { const li = el("li"); const b = el("b"); b.append(el("span", s.severity, "tag " + s.severity), document.createTextNode(s.title)); li.append(b);
        if (s.detail) li.append(el("span", s.detail, "muted small")); ul.append(li); } };
    const vis = r.signals.filter((s) => s.weight !== 0 || s.severity !== "info");
    fill($("signals"), vis.filter((s) => s.group === "risk"), "No phishing indicators found.");
    fill($("posture"), vis.filter((s) => s.group === "posture"), "No configuration issues found.");
    const rc = $("recs"); rc.replaceChildren(); r.recommendations.forEach((t) => rc.append(el("li", t)));
    const c = r.certificate, dl = $("cert"); dl.replaceChildren();
    if (c && c.available) for (const [k, v] of [["Issuer", c.issuer_org || c.issuer_cn], ["Valid", `${c.not_before.slice(0, 10)} → ${c.not_after.slice(0, 10)} (${c.age_days} d old)`], ["Key", c.key], ["Validation", c.validation], ["Transparency", c.has_sct ? "SCT embedded" : "no SCT"], ["Trusted", c.trusted ? "yes" : "NO – " + c.verify_error], ["TLS", c.tls_version]])
      { dl.append(el("dt", k), el("dd", String(v ?? "-"))); }
    else dl.append(el("dt", "Status"), el("dd", "no HTTPS certificate analysed"));
    const i = r.intel; $("intel").textContent = `Status: ${i.status.replace(/_/g, " ")} · ${i.community.reports} report(s)` + (i.feeds.length ? ` · feeds: ${i.feeds.join(", ")}` : "");
    const t = $("hdr"); t.replaceChildren();
    const h = (r.web && r.web.headers) || {};
    for (const [k, v] of Object.entries(h)) { const tr = el("tr"); tr.append(el("td", k), el("td", v ? v.slice(0, 120) : "— missing"), ); t.append(tr); }
    ((r.web && r.web.cookies) || []).forEach((ck) => { const tr = el("tr"); tr.append(el("td", "Cookie " + ck.name), el("td", `Secure:${ck.secure ? "✓" : "✗"} HttpOnly:${ck.httponly ? "✓" : "✗"} SameSite:${ck.samesite ? "✓" : "✗"}`)); t.append(tr); });
    $("repMsg").textContent = "";
  }
  async function report(verdict) {
    let key = null; try { key = localStorage.getItem("pg_key"); } catch (_) {}
    try {
      if (!key) { const name = prompt("Choose a reporter name to register an API key:"); if (!name) return; key = (await call("/api/reporters", { name })).api_key; try { localStorage.setItem("pg_key", key); } catch (_) {} }
      await call("/api/reports", { url: current.url, verdict, category: "phishing" }, key); $("repMsg").textContent = "Thanks, your report was recorded.";
    } catch (e) { $("repMsg").textContent = "Could not submit: " + e.message; }
  }
  $("repBad").addEventListener("click", () => current && report("malicious"));
  $("repGood").addEventListener("click", () => current && report("safe"));
})();
