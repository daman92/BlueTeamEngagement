/* driftwatch operator console — core.
 *
 * SECURITY NOTE (design §9): every value rendered here may be attacker-controlled — process
 * command lines, file paths, certificate subjects and registry keys all land in findings.
 * Nothing in this file (or findings.js / wizard.js) ever assigns innerHTML, outerHTML, or
 * inserts markup built from data. The DOM is constructed node by node and every value goes
 * in via textContent. That is a security control, not a style choice: a malicious command
 * line must not be able to script the analyst's browser. The server's CSP forbids inline
 * script as the second layer.
 */
(function () {
  "use strict";

  var state = {
    token: null, engagements: [], engagement: null, health: null,
    runs: [], run: null, runData: null, view: "dashboard",
    actions: {}, severities: [], hashPolicies: [], operator: "", repoRoot: "",
    cli: { present: false, path: "" }, job: null, jobTimer: null
  };

  var views = {};          // name -> {render(container)}
  var STORE_KEY = "driftwatch.engagement";

  /* ---------------------------------------------------------------- DOM helpers */

  /* el() is the ONLY way this console builds DOM, so the no-markup-from-data rule is
     enforced here rather than left to reviewer discipline: any future caller that reaches
     for an HTML-parsing sink (innerHTML, srcdoc, an on* handler attribute, a javascript:
     URL) gets thrown at, loudly, instead of quietly shipping an XSS. */
  var BANNED_PROPS = /^(inner|outer)HTML$|^srcdoc$|^on/i;
  var URL_ATTRS = /^(href|src|action|formaction|xlink:href|data)$/i;

  function safeUrl(value) {
    /* Same-origin absolute/relative refs only. Blocks javascript:, data:, and any attempt to
       point the report frame somewhere off-box. */
    var url = new URL(String(value), window.location.href);
    if (url.origin !== window.location.origin) {
      throw new Error("refusing a cross-origin URL: " + url.origin);
    }
    return url.href;
  }

  function el(tag, opts, kids) {
    var node = document.createElement(tag);
    opts = opts || {};
    if (typeof opts === "string") { opts = { cls: opts }; }
    if (opts.cls) { node.className = opts.cls; }
    if (opts.text !== undefined && opts.text !== null) { node.textContent = String(opts.text); }
    if (opts.attrs) {
      Object.keys(opts.attrs).forEach(function (k) {
        var v = opts.attrs[k];
        if (v === false || v === null || v === undefined) { return; }
        if (BANNED_PROPS.test(k)) { throw new Error("refused attribute: " + k); }
        node.setAttribute(k, URL_ATTRS.test(k) ? safeUrl(v) : (v === true ? "" : String(v)));
      });
    }
    if (opts.props) {
      Object.keys(opts.props).forEach(function (k) {
        if (BANNED_PROPS.test(k)) { throw new Error("refused property: " + k); }
        node[k] = opts.props[k];
      });
    }
    if (opts.on) {
      Object.keys(opts.on).forEach(function (k) { node.addEventListener(k, opts.on[k]); });
    }
    var list = kids === undefined || kids === null ? [] : (Array.isArray(kids) ? kids : [kids]);
    list.forEach(function (kid) {
      if (kid === null || kid === undefined || kid === false) { return; }
      node.appendChild(typeof kid === "string" || typeof kid === "number"
        ? document.createTextNode(String(kid)) : kid);
    });
    return node;
  }

  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }

  function kv(pairs) {
    var dl = el("dl", "kv");
    pairs.forEach(function (p) {
      if (!p) { return; }
      dl.appendChild(el("dt", { text: p[0] }));
      var dd = el("dd");
      if (p[1] && p[1].nodeType) { dd.appendChild(p[1]); } else { dd.textContent = String(p[1]); }
      if (p[2]) { dd.className = p[2]; }
      dl.appendChild(dd);
    });
    return dl;
  }

  /* `severity` is read out of a findings file. textContent makes it safe to DISPLAY, but it
     is also concatenated into class names, so pin it to the server's severity vocabulary —
     a crafted findings file must not get to choose the analyst's CSS classes either. */
  function sevClass(sev) {
    return state.severities.indexOf(sev) === -1 ? "unknown" : sev;
  }

  function sevBadge(sev) {
    return el("span", { cls: "sev-badge " + sevClass(sev), text: String(sev) });
  }

  function dot(kind, label) {
    return el("span", {}, [el("span", { cls: "status-dot " + kind }), label]);
  }

  function empty(title, detail, actionLabel, onAction) {
    var box = el("div", "empty", [el("strong", { text: title }), detail || ""]);
    if (actionLabel) {
      box.appendChild(el("div", "btn-row", [
        el("button", { cls: "btn primary", text: actionLabel, attrs: { type: "button" },
          on: { click: onAction } })
      ]));
    }
    return box;
  }

  function fmtBytes(n) {
    if (n < 1024) { return n + " B"; }
    if (n < 1024 * 1024) { return (n / 1024).toFixed(1) + " KB"; }
    return (n / (1024 * 1024)).toFixed(1) + " MB";
  }

  function pathLine(p) {
    var span = el("span", { cls: "path", text: p });
    var btn = el("button", { cls: "btn small ghost", text: "copy", attrs: { type: "button" },
      on: { click: function () { copyText(p, btn); } } });
    return el("span", {}, [span, " ", btn]);
  }

  function copyText(value, btn) {
    var done = function () { btn.textContent = "copied"; setTimeout(function () {
      btn.textContent = "copy"; }, 1200); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(done, function () { btn.textContent = "select it"; });
    } else {
      btn.textContent = "select it";
    }
  }

  /* ---------------------------------------------------------------- API */

  function apiUrl(path, params) {
    var url = new URL(path, window.location.origin);
    Object.keys(params || {}).forEach(function (k) {
      if (params[k] !== undefined && params[k] !== null && params[k] !== "") {
        url.searchParams.set(k, params[k]);
      }
    });
    return url.toString();
  }

  function handle(res) {
    return res.json().catch(function () { return { error: "HTTP " + res.status }; })
      .then(function (body) {
        if (!res.ok) { throw new Error(body && body.error ? body.error : "HTTP " + res.status); }
        return body;
      });
  }

  function apiGet(path, params) {
    var headers = {};
    if (state.token) { headers["X-DW-Token"] = state.token; }
    return fetch(apiUrl(path, params), { credentials: "same-origin", headers: headers })
      .then(handle);
  }

  function apiGetText(path, params) {
    var headers = {};
    if (state.token) { headers["X-DW-Token"] = state.token; }
    return fetch(apiUrl(path, params), { credentials: "same-origin", headers: headers })
      .then(function (res) {
        if (!res.ok) { return handle(res); }
        return res.json();
      });
  }

  /* Mutating calls always carry the token in the HEADER (not just the cookie) — that is
     what the server checks alongside the Origin, and together they defeat CSRF. */
  function apiPost(path, body) {
    return fetch(apiUrl(path), {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-DW-Token": state.token || "" },
      body: JSON.stringify(body || {})
    }).then(handle);
  }

  /* ---------------------------------------------------------------- banner / modal */

  function showError(msg) {
    var banner = document.getElementById("banner");
    clear(banner);
    banner.appendChild(el("span", { text: String(msg) }));
    banner.appendChild(el("button", { cls: "btn small", text: "dismiss",
      attrs: { type: "button" }, on: { click: function () { banner.hidden = true; } } }));
    banner.hidden = false;
  }

  function clearError() { document.getElementById("banner").hidden = true; }

  /* opts: {title, body:[nodes], confirmLabel, danger, checkbox:{key,label,note}} ->
     resolves null on cancel, or an object of checkbox values on confirm. */
  function confirmDialog(opts) {
    return new Promise(function (resolve) {
      var root = document.getElementById("modal-root");
      var checks = {};
      var box = el("div", { cls: "modal", attrs: { role: "dialog", "aria-modal": "true" } });
      box.appendChild(el("h2", { text: opts.title }));
      (opts.body || []).forEach(function (n) { box.appendChild(n); });

      if (opts.checkbox) {
        var input = el("input", { attrs: { type: "checkbox" } });
        box.appendChild(el("label", { cls: "f" }, [
          el("span", {}, [input, " ", opts.checkbox.label])
        ]));
        if (opts.checkbox.note) { box.appendChild(el("p", { cls: "hint", text: opts.checkbox.note })); }
        checks.getter = function () { return input.checked; };
      }

      var finish = function (value) {
        document.removeEventListener("keydown", onKey, true);
        root.onclick = null;
        root.hidden = true; clear(root); resolve(value);
      };
      var onKey = function (ev) {
        if (ev.key === "Escape") { ev.stopPropagation(); finish(null); }
      };
      var cancel = el("button", { cls: "btn", text: "cancel", attrs: { type: "button" },
        on: { click: function () { finish(null); } } });
      var go = el("button", {
        cls: "btn " + (opts.danger ? "danger" : "primary"),
        text: opts.confirmLabel || "confirm", attrs: { type: "button" },
        on: { click: function () {
          var out = {};
          if (opts.checkbox) { out[opts.checkbox.key] = checks.getter(); }
          finish(out);
        } }
      });
      box.appendChild(el("div", "modal-actions", [cancel, go]));

      clear(root);
      root.appendChild(box);
      /* The backdrop IS #modal-root (a full-viewport grid); hanging the dismiss on a wrapper
         div only covered the modal's own box, so clicking the dark area did nothing. */
      root.onclick = function (ev) { if (ev.target === root) { finish(null); } };
      root.hidden = false;
      document.addEventListener("keydown", onKey, true);
      /* Danger dialogs (collect reaches the fleet, overwrite replaces the authorization
         record) start focused on CANCEL: a stray Enter must never be the thing that runs
         them. Benign dialogs focus the confirm button so the common path stays one key. */
      (opts.danger ? cancel : go).focus();
    });
  }

  function modalOpen() { return !document.getElementById("modal-root").hidden; }

  /* ---------------------------------------------------------------- actions + console */

  function openConsole(title, status) {
    var box = document.getElementById("console");
    document.getElementById("console-title").textContent = title;
    var st = document.getElementById("console-status");
    st.textContent = status || "running…";
    st.className = "console-status";
    document.getElementById("console-body").textContent = "";
    box.hidden = false;
  }

  function closeConsole() {
    document.getElementById("console").hidden = true;
    if (state.jobTimer) { clearTimeout(state.jobTimer); state.jobTimer = null; }
  }

  function pollJob(jobId, offset) {
    apiGet("/api/job", { id: jobId, offset: offset }).then(function (job) {
      var body = document.getElementById("console-body");
      if (job.chunk) {
        var atBottom = body.scrollTop + body.clientHeight >= body.scrollHeight - 24;
        body.appendChild(document.createTextNode(job.chunk));
        if (atBottom) { body.scrollTop = body.scrollHeight; }
      }
      var st = document.getElementById("console-status");
      if (job.status === "running") {
        st.textContent = "running…";
        state.jobTimer = setTimeout(function () { pollJob(jobId, job.offset); }, 700);
        return;
      }
      st.textContent = job.status === "done" ? "finished (exit 0)" : "failed (exit " + job.rc + ")";
      st.className = "console-status " + (job.status === "done" ? "ok" : "bad");
      state.job = null;
      refreshAfterAction();
    }, function (err) {
      document.getElementById("console-status").textContent = "lost the job: " + err.message;
    });
  }

  function describeAction(verb) {
    var meta = state.actions[verb] || { label: verb, desc: "" };
    return meta;
  }

  function runAction(verb, opts) {
    opts = opts || {};
    if (!state.engagement) { showError("select an engagement first"); return Promise.resolve(); }
    var meta = describeAction(verb);
    return apiPost("/api/action", { verb: verb, engagement: state.engagement, deep: !!opts.deep })
      .then(function (job) {
        state.job = job;
        openConsole(job.label + " · " + state.engagement);
        pollJob(job.job_id, 0);
      }, function (err) { showError(meta.label + ": " + err.message); });
  }

  /* Every action is confirmed. `collect` gets a deliberately blunt dialog: it is the only
     verb here that leaves the control node and touches client machines. */
  function confirmAction(verb) {
    var meta = describeAction(verb);
    var health = state.health || {};
    var body = [];

    if (verb === "collect") {
      var targets = (health.inventory && health.inventory.hosts) || 0;
      body.push(el("div", "warnbox danger", [
        el("h4", { text: "this reaches the fleet" }),
        el("p", { text: "collect connects to client machines and reads state from them. "
          + "It is not a control-node-only operation." })
      ]));
      body.push(kv([
        ["engagement", state.engagement],
        ["client", (health.scope && health.scope.client) || "(not set)"],
        ["authorized by", (health.scope && health.scope.authorized_by) || "(not set)"],
        ["in-scope targets", targets + " host(s) in inventory/hosts.yml"],
        ["scope ranges", ((health.scope && health.scope.in_scope_ranges) || 0) + " CIDR(s)"]
      ]));
      if (!targets) {
        body.push(el("p", { cls: "err", text: "inventory has no hosts — the run will target "
          + "nothing. Generate the inventory from scope.yml first." }));
      }
      body.push(el("p", { cls: "hint", text: "The scope gate runs first and aborts the whole "
        + "run if any resolved target is not affirmatively in scope (design §15.2)." }));
      return confirmDialog({
        title: "Run collect on " + state.engagement + "?",
        body: body, confirmLabel: "collect now", danger: true,
        checkbox: { key: "deep", label: "--deep (hashing, packages, cert stores — slower)",
          note: "Deep collection is the expensive tier; the fast tier is the default." }
      });
    }

    body.push(el("p", { text: meta.desc }));
    body.push(kv([["engagement", state.engagement], ["verb", meta.label],
      ["reaches the fleet", "no — control node only"]]));
    return confirmDialog({ title: "Run " + meta.label + "?", body: body,
      confirmLabel: "run", danger: false });
  }

  function actionButton(verb, extraClass) {
    var meta = describeAction(verb);
    return el("button", {
      cls: "btn " + (extraClass || ""), text: meta.label,
      attrs: { type: "button", title: meta.desc },
      on: { click: function () {
        confirmAction(verb).then(function (answer) {
          if (!answer) { return; }
          runAction(verb, { deep: !!answer.deep });
        });
      } }
    });
  }

  function refreshAfterAction() {
    if (!state.engagement) { return; }
    loadEngagement(state.engagement, state.run).catch(function (err) {
      showError("refresh failed: " + err.message);
    });
  }

  /* ---------------------------------------------------------------- markdown (safe) */

  /* A deliberately small Markdown renderer that builds nodes — no innerHTML, so report
     text (which quotes finding content) can never inject markup. */
  function inlineNodes(line) {
    var out = [];
    line.split("`").forEach(function (part, i) {
      if (i % 2 === 1) { out.push(el("code", { text: part })); return; }
      part.split("**").forEach(function (chunk, j) {
        if (!chunk) { return; }
        out.push(j % 2 === 1 ? el("strong", { text: chunk }) : document.createTextNode(chunk));
      });
    });
    return out;
  }

  function renderMarkdown(text) {
    var frag = document.createDocumentFragment();
    var lines = String(text).split(/\r?\n/);
    var i = 0;
    var flushPara = function (buf) {
      if (buf.length) { frag.appendChild(el("p", {}, inlineNodes(buf.join(" ")))); }
      return [];
    };
    var para = [];
    while (i < lines.length) {
      var line = lines[i];
      if (/^```/.test(line)) {
        para = flushPara(para);
        var code = [];
        i += 1;
        while (i < lines.length && !/^```/.test(lines[i])) { code.push(lines[i]); i += 1; }
        i += 1;
        frag.appendChild(el("pre", {}, [el("code", { text: code.join("\n") })]));
        continue;
      }
      if (/^\s*$/.test(line)) { para = flushPara(para); i += 1; continue; }
      if (/^#{1,6}\s/.test(line)) {
        para = flushPara(para);
        var level = line.match(/^#+/)[0].length;
        frag.appendChild(el("h" + Math.min(level + 1, 6), {},
          inlineNodes(line.replace(/^#+\s*/, ""))));
        i += 1; continue;
      }
      if (/^(-{3,}|_{3,}|\*{3,})\s*$/.test(line)) {
        para = flushPara(para); frag.appendChild(el("hr")); i += 1; continue;
      }
      if (/^\s*\|/.test(line)) {
        para = flushPara(para);
        var rows = [];
        while (i < lines.length && /^\s*\|/.test(lines[i])) { rows.push(lines[i]); i += 1; }
        frag.appendChild(mdTable(rows));
        continue;
      }
      if (/^\s*>/.test(line)) {
        para = flushPara(para);
        var quote = [];
        while (i < lines.length && /^\s*>/.test(lines[i])) {
          quote.push(lines[i].replace(/^\s*>\s?/, "")); i += 1;
        }
        frag.appendChild(el("blockquote", {}, inlineNodes(quote.join(" "))));
        continue;
      }
      if (/^\s*[-*+]\s/.test(line)) {
        para = flushPara(para);
        var ul = el("ul");
        while (i < lines.length && /^\s*[-*+]\s/.test(lines[i])) {
          var item = lines[i].replace(/^\s*[-*+]\s/, "");
          var li = el("li");
          inlineNodes(item).forEach(function (n) { li.appendChild(n); });
          ul.appendChild(li); i += 1;
        }
        frag.appendChild(ul);
        continue;
      }
      para.push(line);
      i += 1;
    }
    flushPara(para);
    return frag;
  }

  function mdTable(rows) {
    var table = el("table");
    var head = el("thead");
    var bodyEl = el("tbody");
    var cells = function (row) {
      return row.trim().replace(/^\||\|$/g, "").split("|").map(function (c) { return c.trim(); });
    };
    rows.forEach(function (row, idx) {
      if (idx === 1 && /^[\s|:-]+$/.test(row)) { return; }
      var tr = el("tr");
      cells(row).forEach(function (c) {
        var cell = el(idx === 0 ? "th" : "td");
        inlineNodes(c).forEach(function (n) { cell.appendChild(n); });
        tr.appendChild(cell);
      });
      (idx === 0 ? head : bodyEl).appendChild(tr);
    });
    table.appendChild(head); table.appendChild(bodyEl);
    return el("div", "scroll-x", [table]);
  }

  /* ---------------------------------------------------------------- dashboard */

  views.dashboard = { render: function (root) {
    root.appendChild(el("h1", { text: "Dashboard" }));
    if (!state.engagements.length) {
      root.appendChild(el("p", { cls: "subtitle",
        text: "No engagement volumes under " + state.repoRoot + "/engagements." }));
      root.appendChild(empty("No engagement yet",
        "An engagement is the top-level boundary: scope, inventory, snapshots, findings and "
        + "the audit trail all live inside it. Start with the Setup wizard — it writes a "
        + "scope.yml from your signed authorization.",
        "Open the Setup wizard", function () { go("setup"); }));
      return;
    }
    if (!state.health) {
      root.appendChild(empty("Select an engagement", "Pick one from the picker above."));
      return;
    }

    var h = state.health;
    root.appendChild(el("p", "subtitle", [
      h.scope.client ? h.scope.client + " · " : "",
      el("span", { cls: "path", text: h.path })
    ]));

    if (!h.scope.exists) {
      root.appendChild(el("div", "warnbox danger", [
        el("h4", { text: "no scope.yml — nothing is authorized" }),
        el("p", { text: "scope.yml is the authorization rail: without it the scope gate "
          + "refuses every run (design §15.2, fail closed)." }),
        el("div", "btn-row", [el("button", { cls: "btn primary", text: "Build scope.yml",
          attrs: { type: "button" }, on: { click: function () { go("setup"); } } })])
      ]));
    } else if (!h.scope.parses) {
      root.appendChild(el("div", "warnbox danger", [
        el("h4", { text: "scope.yml does not parse" }), el("p", { text: h.scope.error })]));
    } else if (h.scope.authorizes_nothing) {
      root.appendChild(el("div", "warnbox danger", [
        el("h4", { text: "in_scope is empty — this engagement authorizes nothing" }),
        el("p", { text: "An empty scope is not a permissive scope: scope_gate refuses to "
          + "generate an inventory or run a play until authorized ranges/hosts are added." })]));
    } else if (!h.scope.authorized_by) {
      root.appendChild(el("div", "warnbox", [
        el("h4", { text: "authorized_by is blank" }),
        el("p", { text: "Record who authorized this engagement and the SOW reference — it is "
          + "the operator's own evidence of staying inside authorization." })]));
    }

    /* --- health strip ------------------------------------------------------- */
    root.appendChild(el("h2", { text: "Run health" }));
    var cards = el("div", "cards");
    cards.appendChild(el("div", "card", [
      el("h3", { text: "authorization" }),
      kv([
        ["scope.yml", h.scope.exists ? (h.scope.parses ? dot("ok", "present, parses")
          : dot("bad", "present, broken")) : dot("bad", "missing")],
        ["authorized_by", h.scope.authorized_by || "(blank)"],
        ["in_scope", h.scope.in_scope_ranges + " range(s), " + h.scope.in_scope_hosts + " host(s)"],
        ["deny", String(h.scope.deny)],
        ["oob_subnets", h.scope.oob_subnets + (h.scope.oob_subnets ? "" : " (all in-band, §13.5)")]
      ])
    ]));
    cards.appendChild(el("div", "card", [
      el("h3", { text: "readiness" }),
      kv([
        ["inventory", h.inventory.generated ? dot("ok", h.inventory.hosts + " host(s)")
          : dot("warn", "not generated")],
        ["vault", h.vault.present ? dot("ok", "present") : dot("warn", "absent")],
        ["hash_policy", (h.scope.settings && h.scope.settings.hash_policy) || "—"],
        ["collector", (h.scope.settings && h.scope.settings.collector_account) || "—"]
      ])
    ]));
    cards.appendChild(el("div", "card", [
      el("h3", { text: "data" }),
      kv([
        ["snapshots", h.counts.snapshot_docs + " doc(s), " + h.counts.snapshot_hosts + " host(s)"],
        ["runs", String(h.counts.runs)],
        ["findings files", String(h.counts.findings_files)],
        ["reports", String(h.counts.reports)]
      ])
    ]));
    cards.appendChild(el("div", "card", [
      el("h3", { text: "latest run" }),
      kv([
        ["run_id", h.latest_run || "(none yet)"],
        ["collected", h.latest.collected_at || "—"],
        ["active findings", h.latest.available ? String(h.latest.active) : "—"],
        ["new this run", h.latest.available ? String(h.latest.new_this_run) : "—"],
        ["suppressed", h.latest.available ? String(h.latest.suppressed) : "—"]
      ])
    ]));
    root.appendChild(cards);

    /* --- severity summary --------------------------------------------------- */
    root.appendChild(el("h2", { text: "Severity summary" + (h.latest_run ? " — " + h.latest_run : "") }));
    if (!h.latest.available) {
      root.appendChild(empty("No findings yet",
        "Run collect (or diff, if snapshots already exist) to produce a findings set."));
    } else {
      var grid = el("div", "sev-grid");
      state.severities.forEach(function (sev) {
        grid.appendChild(el("div", { cls: "sev-tile " + sev }, [
          el("div", { cls: "n", text: String(h.latest.by_severity[sev] || 0) }),
          el("div", { cls: "l", text: sev })
        ]));
      });
      root.appendChild(grid);
      root.appendChild(el("p", "count-note", [
        h.latest.active + " active", h.latest.suppressed
          ? " · " + h.latest.suppressed + " suppressed (kept, never dropped)" : "",
        " · ", el("button", { cls: "btn small ghost", text: "open findings",
          attrs: { type: "button" }, on: { click: function () { go("findings"); } } })
      ]));
      if (h.latest.error) { root.appendChild(el("p", { cls: "err", text: h.latest.error })); }
    }

    /* --- quick actions ------------------------------------------------------ */
    root.appendChild(el("h2", { text: "Quick actions" }));
    if (!state.cli.present) {
      root.appendChild(el("div", "warnbox", [
        el("h4", { text: "bin/driftwatch not found" }),
        el("p", { text: "Actions that shell out to the CLI will fail. Expected at: "
          + state.cli.path })]));
    }
    var row = el("div", "btn-row", [
      actionButton("doctor", "primary"),
      actionButton("scope-generate"),
      actionButton("diff"),
      actionButton("report"),
      actionButton("collect", "danger")
    ]);
    root.appendChild(row);
    root.appendChild(el("p", "hint", [
      "The GUI can only ask for these five verbs. Response (propose/approve/rollback) and "
      + "teardown are not reachable from here by design — the response layer is human-gated "
      + "at the terminal and must not grow a web UI (design §13.6)."
    ]));
  } };

  /* ---------------------------------------------------------------- reports */

  views.reports = { render: function (root) {
    root.appendChild(el("h1", { text: "Reports" }));
    root.appendChild(el("p", "subtitle", ["Rendered per-run reports from ",
      el("span", { cls: "path", text: "reports/<run_id>.{md,html}" }),
      ". HTML is shown inside a fully sandboxed frame (no script, opaque origin)."]));
    if (!state.engagement) { root.appendChild(empty("Select an engagement")); return; }

    var listBox = el("div");
    var viewer = el("div");
    root.appendChild(listBox);
    root.appendChild(viewer);

    apiGet("/api/reports", { engagement: state.engagement }).then(function (data) {
      clear(listBox);
      if (!data.reports.length) {
        listBox.appendChild(empty("No reports yet",
          "Run `report` for a run that already has findings.",
          "Run report", function () {
            confirmAction("report").then(function (a) { if (a) { runAction("report"); } });
          }));
        return;
      }
      var table = el("table");
      var thead = el("thead", {}, [el("tr", {}, [
        el("th", { text: "run" }), el("th", { text: "formats" }),
        el("th", { text: "modified" }), el("th", { text: "path" }), el("th", { text: "" })
      ])]);
      var tbody = el("tbody");
      data.reports.forEach(function (rep) {
        var fmts = Object.keys(rep.formats).sort();
        var first = rep.formats[fmts[0]];
        var buttons = el("div", "btn-row");
        fmts.forEach(function (fmt) {
          buttons.appendChild(el("button", {
            cls: "btn small", text: "view " + fmt, attrs: { type: "button" },
            on: { click: function () { showReport(viewer, rep.run_id, fmt, rep.formats[fmt]); } }
          }));
        });
        tbody.appendChild(el("tr", {}, [
          el("td", { cls: "mono nowrap", text: rep.run_id }),
          el("td", { text: fmts.map(function (f) {
            return f + " (" + fmtBytes(rep.formats[f].size) + ")"; }).join(", ") }),
          el("td", { cls: "nowrap dim", text: first.modified }),
          el("td", {}, [pathLine(first.path)]),
          el("td", {}, [buttons])
        ]));
      });
      table.appendChild(thead); table.appendChild(tbody);
      listBox.appendChild(el("div", "scroll-x", [table]));
      var preferred = state.run && data.reports.some(function (r) { return r.run_id === state.run; })
        ? state.run : data.reports[0].run_id;
      var entry = data.reports.filter(function (r) { return r.run_id === preferred; })[0];
      var fmt = entry.formats.html ? "html" : "md";
      showReport(viewer, preferred, fmt, entry.formats[fmt]);
    }, function (err) { showError("reports: " + err.message); });
  } };

  function showReport(container, runId, fmt, meta) {
    clear(container);
    container.appendChild(el("h2", { text: runId + " · " + fmt }));
    container.appendChild(el("p", "count-note", [
      "hand this file over: ", pathLine(meta.path), " · ", fmtBytes(meta.size)]));
    if (fmt === "html") {
      /* Sandboxed with no allow-* tokens at all: opaque origin, scripts disabled, forms
         disabled. The server sends `Content-Security-Policy: sandbox` on this route too. */
      var frame = el("iframe", { cls: "report-frame", attrs: {
        sandbox: "", referrerpolicy: "no-referrer", title: "report " + runId,
        src: apiUrl("/api/report/frame", { engagement: state.engagement, run: runId })
      } });
      container.appendChild(frame);
      return;
    }
    var host = el("div", "md");
    container.appendChild(host);
    apiGetText("/api/report", { engagement: state.engagement, run: runId, fmt: "md" })
      .then(function (data) { host.appendChild(renderMarkdown(data.text)); },
        function (err) { showError("report: " + err.message); });
  }

  /* ---------------------------------------------------------------- audit log */

  views.audit = { render: function (root) {
    root.appendChild(el("h1", { text: "Audit log" }));
    root.appendChild(el("p", "subtitle", ["Append-only record of every run and every scope "
      + "denial — read-only here. It is the operator's evidence of staying inside "
      + "authorization (design §15.2)."]));
    if (!state.engagement) { root.appendChild(empty("Select an engagement")); return; }

    var filter = el("input", { attrs: { type: "text", placeholder: "filter…",
      "data-search": "1", "aria-label": "Filter audit lines" } });
    root.appendChild(el("div", "toolbar", [
      el("label", { cls: "field grow" }, [el("span", "field-label", ["filter"]), filter]),
      el("button", { cls: "btn", text: "reload", attrs: { type: "button" },
        on: { click: function () { render(); } } })
    ]));
    var out = el("div");
    root.appendChild(out);

    /* One listener for the life of the view. Re-registering it inside render() meant every
       "reload" stacked another handler (plus its now-detached table) onto the same input. */
    var drawCurrent = null;
    filter.addEventListener("input", function () { if (drawCurrent) { drawCurrent(); } });

    function render() {
      apiGet("/api/audit", { engagement: state.engagement, limit: 2000 }).then(function (data) {
        clear(out);
        drawCurrent = null;
        if (!data.exists || !data.lines.length) {
          out.appendChild(empty("No audit entries yet",
            "Every verb the CLI or this console runs appends one line here."));
          return;
        }
        out.appendChild(el("p", "count-note", [data.total + " line(s) · ",
          pathLine(data.path)]));
        var tbody = el("tbody");
        var table = el("table", {}, [
          el("thead", {}, [el("tr", {}, [
            el("th", { text: "when" }), el("th", { text: "verb" }), el("th", { text: "run" }),
            el("th", { text: "operator" }), el("th", { text: "outcome" })])]),
          tbody
        ]);
        var draw = function () {
          var needle = filter.value.trim().toLowerCase();
          clear(tbody);
          var shown = 0;
          data.lines.forEach(function (line) {
            if (needle && line.raw.toLowerCase().indexOf(needle) === -1) { return; }
            shown += 1;
            var bad = /DENY|ABORT|FAIL/i.test(line.outcome);
            tbody.appendChild(el("tr", {}, [
              el("td", { cls: "mono nowrap dim", text: line.ts }),
              el("td", { cls: "mono nowrap", text: line.verb }),
              el("td", { cls: "mono nowrap dim", text: line.run_id }),
              el("td", { cls: "nowrap", text: line.operator }),
              el("td", { cls: bad ? "err" : "", text: line.outcome })
            ]));
          });
          if (!shown) {
            tbody.appendChild(el("tr", {}, [el("td", { cls: "dim",
              attrs: { colspan: 5 }, text: "nothing matches that filter" })]));
          }
        };
        drawCurrent = draw;
        draw();
        out.appendChild(el("div", "scroll-x", [table]));
      }, function (err) { showError("audit: " + err.message); });
    }
    render();
  } };

  /* ---------------------------------------------------------------- shell wiring */

  function go(view) {
    state.view = view;
    document.querySelectorAll(".nav-item").forEach(function (btn) {
      btn.setAttribute("aria-current", btn.getAttribute("data-view") === view ? "true" : "false");
    });
    ["dashboard", "findings", "matrix", "reports", "setup", "audit"].forEach(function (name) {
      document.getElementById("view-" + name).hidden = name !== view;
    });
    renderView();
  }

  function renderView() {
    var root = document.getElementById("view-" + state.view);
    clear(root);
    /* Views install their own Escape behaviour; drop the previous one first, or Escape keeps
       poking at a table that was torn down two views ago. */
    window.DW.onEscape = null;
    var view = views[state.view];
    if (!view) { root.appendChild(empty("Not implemented")); return; }
    try {
      view.render(root);
    } catch (err) {
      root.appendChild(empty("This view failed to render", String(err && err.message)));
    }
  }

  function fillEngagementPicker() {
    var picker = document.getElementById("engagement-picker");
    clear(picker);
    if (!state.engagements.length) {
      picker.appendChild(el("option", { text: "(none)", attrs: { value: "" } }));
      picker.disabled = true;
      return;
    }
    picker.disabled = false;
    state.engagements.forEach(function (eng) {
      picker.appendChild(el("option", {
        text: eng.id + (eng.has_scope ? "" : "  (no scope.yml)"),
        attrs: { value: eng.id }
      }));
    });
    if (state.engagement) { picker.value = state.engagement; }
  }

  function fillRunPicker() {
    var picker = document.getElementById("run-picker");
    clear(picker);
    if (!state.runs.length) {
      picker.appendChild(el("option", { text: "(no runs)", attrs: { value: "" } }));
      picker.disabled = true;
      return;
    }
    picker.disabled = false;
    state.runs.forEach(function (runId, idx) {
      picker.appendChild(el("option", {
        text: runId + (idx === 0 ? "  (latest)" : ""), attrs: { value: runId }
      }));
    });
    if (state.run) { picker.value = state.run; }
  }

  function loadRun(runId) {
    if (!runId) { state.run = null; state.runData = null; return Promise.resolve(); }
    return apiGet("/api/run", { engagement: state.engagement, run: runId })
      .then(function (data) { state.run = runId; state.runData = data; });
  }

  function refreshEngagements() {
    return apiGet("/api/state").then(function (data) {
      state.engagements = data.engagements || [];
      fillEngagementPicker();
      return data;
    });
  }

  function loadEngagement(id, keepRun) {
    state.engagement = id;
    window.localStorage.setItem(STORE_KEY, id);
    var picker = document.getElementById("engagement-picker");
    var known = Array.prototype.some.call(picker.options, function (o) { return o.value === id; });
    if (known) { picker.value = id; }
    return apiGet("/api/engagement", { engagement: id }).then(function (health) {
      state.health = health;
      state.runs = health.runs || [];
      fillRunPicker();
      var runId = keepRun && state.runs.indexOf(keepRun) !== -1 ? keepRun : state.runs[0];
      return loadRun(runId);
    }).then(function () {
      fillRunPicker();
      clearError();
      renderView();
    });
  }

  function boot() {
    document.querySelectorAll(".nav-item").forEach(function (btn) {
      btn.addEventListener("click", function () { go(btn.getAttribute("data-view")); });
    });
    document.getElementById("console-close").addEventListener("click", closeConsole);
    document.getElementById("engagement-picker").addEventListener("change", function (ev) {
      loadEngagement(ev.target.value).catch(function (err) { showError(err.message); });
    });
    document.getElementById("run-picker").addEventListener("change", function (ev) {
      loadRun(ev.target.value).then(renderView, function (err) { showError(err.message); });
    });

    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape") {
        if (modalOpen()) { return; }          // the dialog's own handler owns Escape
        if (!document.getElementById("console").hidden) { closeConsole(); return; }
        if (typeof window.DW.onEscape === "function") { window.DW.onEscape(); }
        return;
      }
      /* While a confirmation is up the shortcuts are off. Otherwise "3" would swap the view
         out from under an open dialog and the analyst would be confirming an action against
         a screen they can no longer see. */
      if (modalOpen()) { return; }
      var tag = (ev.target && ev.target.tagName) || "";
      var typing = tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
      if (ev.key === "/" && !typing) {
        var box = document.querySelector("#view-" + state.view + " [data-search]");
        if (box) { ev.preventDefault(); box.focus(); box.select(); }
        return;
      }
      if (!typing && !ev.ctrlKey && !ev.metaKey && !ev.altKey) {
        var order = ["dashboard", "findings", "matrix", "reports", "setup", "audit"];
        var idx = "123456".indexOf(ev.key);
        if (idx !== -1) { go(order[idx]); }
      }
    });

    apiGet("/api/state").then(function (data) {
      state.token = data.csrf_token;
      state.engagements = data.engagements || [];
      state.actions = data.actions || {};
      state.severities = data.severities || [];
      state.hashPolicies = data.hash_policies || [];
      state.operator = data.operator;
      state.repoRoot = data.repo_root;
      state.cli = data.cli || { present: false, path: "" };
      document.getElementById("operator-badge").textContent =
        "operator " + data.operator + " · " + data.version;
      document.getElementById("repo-hint").textContent = data.repo_root;
      fillEngagementPicker();

      var remembered = window.localStorage.getItem(STORE_KEY);
      var ids = state.engagements.map(function (e) { return e.id; });
      var initial = data.engagement && ids.indexOf(data.engagement) !== -1 ? data.engagement
        : (remembered && ids.indexOf(remembered) !== -1 ? remembered : ids[0]);
      go("dashboard");
      if (initial) {
        document.getElementById("engagement-picker").value = initial;
        return loadEngagement(initial);
      }
      fillRunPicker();
      renderView();
      return null;
    }).catch(function (err) {
      showError("could not talk to the server: " + err.message
        + " — reopen the tokenised URL printed by `driftwatch gui`.");
    });
  }

  /* Shared surface for findings.js / wizard.js. */
  window.DW = {
    state: state, views: views, el: el, clear: clear, kv: kv, empty: empty,
    sevBadge: sevBadge, sevClass: sevClass, dot: dot, pathLine: pathLine, fmtBytes: fmtBytes,
    apiGet: apiGet, apiPost: apiPost, showError: showError, clearError: clearError,
    confirmDialog: confirmDialog, confirmAction: confirmAction, runAction: runAction,
    actionButton: actionButton, renderMarkdown: renderMarkdown, go: go,
    renderView: renderView, loadEngagement: loadEngagement,
    refreshEngagements: refreshEngagements, onEscape: null
  };

  document.addEventListener("DOMContentLoaded", boot);
}());
