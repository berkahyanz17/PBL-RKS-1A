/* app.js — minimal, demo-safe JS for Weft UI */
(function () {
  function isTyping() {
    const el = document.activeElement;
    if (!el) return false;
    const tag = el.tagName.toLowerCase();
    return tag === "input" || tag === "textarea" || tag === "select";
  }

  function pick(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
  }

  function chance(p) {
    return Math.random() < p;
  }

  function norm(v) {
    return String(v ?? "").trim().toLowerCase();
  }

  function isAny(v) {
    const x = norm(v);
    return x === "" || x === "any" || x === "*";
  }

  function getCmdBox() {
    return document.getElementById("cmdbox") || document.getElementById("cmdbox2");
  }

  window.copyCmd = function copyCmd(textareaId) {
    const el = document.getElementById(textareaId) || getCmdBox();
    if (!el) return;
    const lines = el.value
      .split("\n")
      .filter((l) => l.trim() && !l.trim().startsWith("#"));
    navigator.clipboard.writeText(lines.join("\n")).then(() => {
      alert("Commands copied!");
    });
  };
  function copyText(id){
      const el = document.getElementById(id);
      if (!el) return;
      el.select();
      el.setSelectionRange(0, 99999);
      navigator.clipboard.writeText(el.value).then(() => {
        alert("Copied!");
      });
      return;
    }
  function setupThemeToggle() {
    const btn = document.getElementById("themeToggle");
    if (!btn) return;

    function applyTheme(dark) {
      document.body.classList.add("no-transitions");
      document.documentElement.classList.toggle("dark", dark);
      document.body.classList.toggle("dark", dark);
      localStorage.setItem("theme", dark ? "dark" : "light");
      btn.textContent = dark ? "☀️" : "🌙";
      setTimeout(() => document.body.classList.remove("no-transitions"), 30);
    }

    const saved = localStorage.getItem("theme");
    if (saved === "dark") applyTheme(true);

    btn.addEventListener("click", () => {
      applyTheme(!document.body.classList.contains("dark"));
    });
  }

  function setupScrollPreserve() {
    if (document.body.dataset.page !== "index") return;

    window.addEventListener("load", () => {
      const y = sessionStorage.getItem("scrollY");
      const should = sessionStorage.getItem("restoreScroll") === "1";
      if (y !== null && should) window.scrollTo(0, parseInt(y, 10));
      sessionStorage.removeItem("scrollY");
      sessionStorage.removeItem("restoreScroll");
    });

    document.querySelectorAll("form").forEach((form) => {
      form.addEventListener("submit", () => {
        sessionStorage.setItem("scrollY", String(window.scrollY));
        sessionStorage.setItem("restoreScroll", "1");
      });
    });
  }

  function setupShortcuts() {
    const hasPresetForms =
      document.querySelector("form[action='/preset/professional']") &&
      document.querySelector("form[action='/preset/safer']");
    document.addEventListener("keydown", function (e) {
      if (isTyping()) return;
      if (!hasPresetForms){
        switch (e.key.toLowerCase()) {
          case "l":
            window.location.href = "/logs";
            break;
          case "h":
            window.location.href = "/";
            break;
          case "a":
            window.location.href = "/about";
            break;
        }
        return;
      }else{
      switch (e.key.toLowerCase()) {
        case "p":
          document.querySelector("form[action='/preset/professional'] button")?.click();
          break;
        case "s":
          document.querySelector("form[action='/preset/safer'] button")?.click();
          break;
        case "e":
          window.location.href = "/export";
          break;
        case "l":
          window.location.href = "/logs";
          break;
        case "h":
          window.location.href = "/";
          break;
        case "a":
          window.location.href = "/about";
          break;
        case "d":
          alert("To disable firewall safely, run:\n\n./scripts/disable.sh");
          break;
      }}
    });
  }

  function setupLiveLogs() {
    const body = document.getElementById("logBody");
    if (!body) return;

    let lastId = 0;
    body.querySelectorAll("tr").forEach((tr) => {
      const id = parseInt(tr.dataset.id || "0", 10);
      lastId = Math.max(lastId, id);
    });

    async function fetchLiveLogs() {
      try {
        const res = await fetch(`/logs_tail?since=${lastId}`, { cache: "no-store" });
        const data = await res.json();
        const rows = data.rows || [];

        rows.forEach((r) => {
          const tr = document.createElement("tr");
          tr.dataset.id = String(r[0]);
          tr.innerHTML = `
            <td>${r[1]}</td>
            <td>${r[2]}</td>
            <td>${r[3]}</td>
            <td>${r[4]} → ${r[5]}</td>
            <td>${r[6]}</td>
            <td>${r[7]}</td>
            <td>${r[8]}</td>
          `;
          body.appendChild(tr);
          lastId = r[0];
        });
      } catch (_) {}
    }

    setInterval(fetchLiveLogs, 2000);
  }
  function recommendQuickTest(rule) {
    const action = norm(rule.action) === "drop" ? "DROP" : "ACCEPT";
    const proto = norm(rule.proto) || "any";
    const dst = norm(rule.dst) || "any";
    const dport = norm(rule.dport) || "any";

    const lines = [];
    lines.push(`# Rule quick test (auto-generated)`);
    lines.push(`# Rule: ${action} proto=${proto} dst=${dst} dport=${dport}`);
    lines.push("");

    const targetIp = !isAny(dst) ? dst : "8.8.8.8";
    const dnsServer = !isAny(dst) ? dst : "8.8.8.8";

    const expected =
      action === "ACCEPT"
        ? "# should WORK (allowed)"
        : "# should FAIL / timeout (blocked)";

    if (proto === "icmp") {
      lines.push(`ping -c 2 ${targetIp}`);
      lines.push(expected);
      return lines.join("\n");
    }

    const portNum = parseInt(dport, 10);
    const hasPort = !isNaN(portNum) && !isAny(dport);

    if ((proto === "tcp" || proto === "any") && hasPort) {
      if (portNum === 80) {
        lines.push(`curl -I http://example.com`);
        lines.push(expected);
        return lines.join("\n");
      }
      if (portNum === 443) {
        lines.push(`curl -I https://example.com`);
        lines.push(expected);
        return lines.join("\n");
      }
      if (portNum === 22) {
        lines.push(`nc -vz ${targetIp} 22`);
        lines.push(expected);
        lines.push("");
        lines.push(`# tip: if nc isn't installed: sudo apt install -y netcat-openbsd`);
        return lines.join("\n");
      }

      lines.push(`nc -vz ${targetIp} ${portNum}`);
      lines.push(expected);
      lines.push("");
      lines.push(`# tip: if nc isn't installed: sudo apt install -y netcat-openbsd`);
      return lines.join("\n");
    }

    if ((proto === "udp" || proto === "any") && hasPort) {
      if (portNum === 53) {
        lines.push(`dig @${dnsServer} example.com`);
        lines.push(expected);
        lines.push("");
        lines.push(`# Install dig if needed:`);
        lines.push(`# sudo apt install -y dnsutils`);
        return lines.join("\n");
      }

      if (portNum === 123) {
        lines.push(`# NTP quick probe (udp/123)`);
        lines.push(`nc -vu ${targetIp} 123`);
        lines.push(expected);
        lines.push("");
        lines.push(`# tip: if nc isn't installed: sudo apt install -y netcat-openbsd`);
        return lines.join("\n");
      }

      lines.push(`# UDP test is less direct than TCP.`);
      lines.push(`# Suggested generic probe (may not conclusively prove allow/deny):`);
      lines.push(`nc -vu ${targetIp} ${portNum}`);
      lines.push(expected);
      lines.push("");
      lines.push(`# tip: if nc isn't installed: sudo apt install -y netcat-openbsd`);
      return lines.join("\n");
    }

    lines.push(`# This rule is broad (proto/port is 'any'). Try common tests:`);
    lines.push("");
    lines.push(`curl -I https://example.com`);
    lines.push(expected);
    lines.push("");
    lines.push(`ping -c 2 ${targetIp}`);
    lines.push(expected);
    lines.push("");
    lines.push(`# If dig is missing: sudo apt install -y dnsutils`);
    return lines.join("\n");
  }

  function getNewestRuleFromTable() {
    const tables = Array.from(document.querySelectorAll("table.table"));
    const rulesTable = tables.find((t) => {
      const th = Array.from(t.querySelectorAll("th")).map((x) => x.textContent.trim().toLowerCase());
      return th.includes("action") && th.includes("proto") && th.includes("dport");
    });
    if (!rulesTable) return null;

    const rows = Array.from(rulesTable.querySelectorAll("tr")).slice(1);
    let best = null;
    let bestId = -1;

    for (const tr of rows) {
      const tds = tr.querySelectorAll("td");
      if (tds.length < 6) continue;

      const id = parseInt(tds[0].textContent.trim(), 10);
      if (isNaN(id)) continue;

      const action = tds[1].textContent.trim();
      const proto = tds[2].textContent.trim();
      const src = tds[3]?.textContent.trim() ?? "any";
      const dst = tds[4]?.textContent.trim() ?? "any";
      const dport = tds[5]?.textContent.trim() ?? "any";
      const comment = tds[6]?.textContent.trim() ?? "";

      if (comment === "Allow localhost") continue;
      if (comment.toLowerCase().startsWith("default allow")) continue;
      if (comment.toLowerCase().startsWith("default deny")) continue;

      if (id > bestId) {
        bestId = id;
        best = { id, action, proto, src, dst, dport };
      }
    }

    return best;
  }
  
  function setupQuickTestPersistence() {
    const cmdbox = getCmdBox();
    if (!cmdbox) return;

    const params = new URLSearchParams(window.location.search);
    const preset = (params.get("preset") || "").toLowerCase();
    const presetActive = preset === "professional" || preset === "safer";

    window.addEventListener("load", () => {
      const saved = sessionStorage.getItem("quickTestCmds");
      if (saved) {
        cmdbox.value = saved;
        sessionStorage.removeItem("quickTestCmds");
        return;
      }

      if (presetActive) {
        return;
      }

      const newest = getNewestRuleFromTable();
      if (newest) cmdbox.value = recommendQuickTest(newest);
    });
  }

  function setupQuickTestFromAddRule() {
    const form = document.querySelector("form[action='/add']");
    const cmdbox = getCmdBox();
    if (!form || !cmdbox) return;

    form.addEventListener("submit", () => {
      const rule = {
        action: form.elements.action?.value ?? "ACCEPT",
        proto: form.elements.proto?.value ?? "any",
        src: form.elements.src?.value ?? "any",
        dst: form.elements.dst?.value ?? "any",
        dport: form.elements.dport?.value ?? "any",
      };

      const txt = recommendQuickTest(rule);
      cmdbox.value = txt;
      sessionStorage.setItem("quickTestCmds", txt);
    });
  }

  function setupRandomRule() {
    const btn = document.getElementById("randomRuleBtn");
    const form = document.querySelector("form[action='/add']");
    if (!btn || !form) return;

    const popularIps = [
      "any",
      "127.0.0.1",
      "10.0.2.15",
      "192.168.1.10",
      "8.8.8.8",
      "1.1.1.1",
      "9.9.9.9",
      "208.67.222.222",
    ];

    const tcpPorts = [22, 25, 80, 443, 587, 8080, 8443, 3306, 5432, 6379];
    const udpPorts = [53, 67, 68, 123, 161, 500, 4500];
    const protos = ["tcp", "tcp", "udp", "icmp", "any"];

    function genRule() {
      const proto = pick(protos);

      let dport = "any";
      if (proto === "tcp") dport = String(pick(tcpPorts));
      if (proto === "udp") dport = String(pick(udpPorts));
      if (proto === "icmp") dport = "any";
      if (proto === "any") dport = chance(0.35) ? String(pick([80, 443, 53, 22])) : "any";

      let src = "any";
      let dst = "any";
      if (chance(0.5)) src = pick(popularIps);
      else dst = pick(popularIps);

      const action = chance(0.65) ? "ACCEPT" : "DROP";

      const pn = parseInt(dport, 10);
      let label = "traffic";
      if (proto === "icmp") label = "ICMP ping";
      else if (pn === 80) label = "HTTP";
      else if (pn === 443) label = "HTTPS";
      else if (pn === 53) label = "DNS";
      else if (pn === 22) label = "SSH";
      else if (pn === 123) label = "NTP";
      else if (pn === 3306) label = "MySQL";
      else if (pn === 5432) label = "Postgres";
      else if (pn === 6379) label = "Redis";
      else if (!isNaN(pn)) label = `${proto.toUpperCase()}/${pn}`;

      const comment = (action === "DROP" ? "Block " : "Allow ") + label;
      return { action, proto, src, dst, dport, comment };
    }

    function fill(rule) {
      if (form.elements.action) form.elements.action.value = rule.action;
      if (form.elements.proto) form.elements.proto.value = rule.proto;
      if (form.elements.src) form.elements.src.value = rule.src;
      if (form.elements.dst) form.elements.dst.value = rule.dst;
      if (form.elements.dport) form.elements.dport.value = rule.dport;
      if (form.elements.comment) form.elements.comment.value = rule.comment;
    }

    btn.addEventListener("click", () => fill(genRule()));
  }
  function startStatsPolling() {
    const hasAny =
      document.getElementById("pktCount") ||
      document.getElementById("m_total") ||
      document.getElementById("m_accept") ||
      document.getElementById("m_drop") ||
      document.getElementById("m_pps") ||
      document.getElementById("warnInput") ||
      document.getElementById("dropInput") ||
      document.getElementById("dosLight");

    if (!hasAny) return;

    let lastPktShown = 0;
    let animTimer = null;

    function animatePktTo(target) {
      const el = document.getElementById("pktCount");
      if (!el) return;

      target = Number(target) || 0;

      if (animTimer) {
        clearInterval(animTimer);
        animTimer = null;
      }

      if (target < lastPktShown) {
        lastPktShown = target;
        el.textContent = String(target);
        return;
      }

      let current = lastPktShown;
      const step = Math.max(1, Math.floor((target - current) / 5));

      animTimer = setInterval(() => {
        if (current >= target) {
          clearInterval(animTimer);
          animTimer = null;
          lastPktShown = target;
          el.textContent = String(target);
        } else {
          current += step;
          if (current > target) current = target;
          el.textContent = String(current);
        }
      }, 40);
    }

    async function tick() {
      try {
        const r = await fetch("/stats", { cache: "no-store" });
        const s = await r.json();

        const total = Number((s.total ?? s.packets) ?? 0);
        if (document.getElementById("pktCount")) animatePktTo(total);

        const t = document.getElementById("m_total");
        if (t) t.textContent = String(s.total ?? 0);

        const a = document.getElementById("m_accept");
        if (a) a.textContent = String(s.accept ?? 0);

        const d = document.getElementById("m_drop");
        if (d) d.textContent = String(s.drop ?? 0);

        const p = document.getElementById("m_pps");
        if (p) p.textContent = String(s.pps ?? 0);

        const wIn = document.getElementById("warnInput");
        const drIn = document.getElementById("dropInput");
        if (wIn && wIn.value.trim() === "") wIn.value = String(s.warn_5s ?? 50);
        if (drIn && drIn.value.trim() === "") drIn.value = String(s.drop_5s ?? 110);

        const light = document.getElementById("dosLight");
        if (light) {
          light.classList.remove("warn", "drop");
          if (s.dos_state === "warn") light.classList.add("warn");
          if (s.dos_state === "drop") light.classList.add("drop");
        }
      } catch (e) {
        const pkt = document.getElementById("pktCount");
        if (pkt) pkt.textContent = "—";
        if (animTimer) {
          clearInterval(animTimer);
          animTimer = null;
        }

        const t = document.getElementById("m_total");
        const a = document.getElementById("m_accept");
        const d = document.getElementById("m_drop");
        const p = document.getElementById("m_pps");
        if (t) t.textContent = "—";
        if (a) a.textContent = "—";
        if (d) d.textContent = "—";
        if (p) p.textContent = "—";
      }
    }

    tick();
    setInterval(tick, 2000);
  }
    const panel = document.getElementById("codePanel");
    const title = document.getElementById("codeTitle");
    const hint  = document.getElementById("codeHint");
    const close = document.getElementById("codeClose");
    const copy  = document.getElementById("codeCopy");

    const chips = Array.from(document.querySelectorAll(".chip-btn"));
    const snippets = Array.from(document.querySelectorAll(".code-snippet"));

    function show(id){
      panel.hidden = false;
      snippets.forEach(s => s.hidden = (s.id !== id));
      chips.forEach(c => c.classList.toggle("active", c.dataset.code === id));

      const active = document.getElementById(id);
      title.textContent = active?.dataset?.title || "Code Preview";
      hint.textContent = "Short excerpt from the program.";
    }

    chips.forEach(btn => btn.addEventListener("click", () => show(btn.dataset.code)));

    close?.addEventListener("click", () => {
      panel.hidden = true;
      chips.forEach(c => c.classList.remove("active"));
      snippets.forEach(s => s.hidden = true);
      title.textContent = "Code Preview";
      hint.textContent = "Click a chip to view the relevant excerpt.";
    });

    copy?.addEventListener("click", async () => {
      const active = snippets.find(s => !s.hidden);
      const pre = active?.querySelector("[data-copy]");
      if (!pre) return;

      try{
        await navigator.clipboard.writeText(pre.textContent);
      }catch(_){
        // fallback
        const ta = document.createElement("textarea");
        ta.value = pre.textContent;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        ta.remove();
      }
    });
    
  // ---------- boot ----------
  setupThemeToggle();
  setupScrollPreserve();
  setupShortcuts();
  setupLiveLogs();

  setupRandomRule();
  setupQuickTestFromAddRule();
  setupQuickTestPersistence();

  startStatsPolling();
})();
