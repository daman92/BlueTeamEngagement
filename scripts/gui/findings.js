/* driftwatch operator console — findings browser + fleet matrix.
 *
 * Findings carry attacker-controlled strings (process args, file paths, cert subjects).
 * Every node below is created with createElement and filled with textContent; there is no
 * innerHTML anywhere. See the header of app.js.
 *
 * Ordering matches the report: severity first (critical -> info, the order the server sends
 * from driftwatch_common.SEVERITIES / severity_rank), then fingerprint.
 */
(function () {
  "use strict";

  var DW = window.DW;
  var el = DW.el, clear = DW.clear, kv = DW.kv, empty = DW.empty, sevBadge = DW.sevBadge;
  var sevClass = DW.sevClass;
  var state = DW.state;

  var filters = {
    sev: null,               // Set of severities; null = all
    host: "", category: "", q: "", suppressed: "all",
    sortKey: "severity", sortDir: 1, expanded: null
  };

  function severityRank(sev) {
    var idx = state.severities.indexOf(sev);
    return idx === -1 ? state.severities.length : idx;
  }

  function activeSeverities() {
    if (!filters.sev) { filters.sev = new Set(state.severities); }
    return filters.sev;
  }

  function isObject(v) { return v && typeof v === "object" && !Array.isArray(v); }

  function compact(v) {
    if (v === undefined) { return "(absent)"; }
    if (v === null) { return "null"; }
    return typeof v === "string" ? v : JSON.stringify(v);
  }

  function pretty(v) {
    if (typeof v === "string") { return v; }
    try { return JSON.stringify(v, null, 2); } catch (err) { return String(v); }
  }

  /* ---------------------------------------------------------------- diff panel */

  function diffBlock(f) {
    var pre = el("pre", "diff");
    var d = f.detail || {};
    var before = d.before, after = d.after;
    var identity = d.identity;
    var line = function (cls, sign, text) {
      pre.appendChild(el("span", { cls: cls, text: sign + " " + text + "\n" }));
    };
    var block = function (cls, sign, value) {
      pretty(value).split("\n").forEach(function (l) { line(cls, sign, l); });
    };

    if (f.change_type === "changed" && isObject(before) && isObject(after)) {
      var keys = Object.keys(before).concat(Object.keys(after))
        .filter(function (k, i, a) { return a.indexOf(k) === i; }).sort();
      keys.forEach(function (k) {
        var bv = before[k], av = after[k];
        if (JSON.stringify(bv) === JSON.stringify(av)) {
          line("ctx", " ", k + ": " + compact(bv));
        } else {
          if (bv !== undefined) { line("del", "-", k + ": " + compact(bv)); }
          if (av !== undefined) { line("add", "+", k + ": " + compact(av)); }
        }
      });
      return pre;
    }
    if (f.change_type === "added") { block("add", "+", after !== undefined && after !== null ? after : identity); return pre; }
    if (f.change_type === "removed") { block("del", "-", before !== undefined && before !== null ? before : identity); return pre; }
    if (f.change_type === "coverage_gap") {
      block("gap", "!", after !== undefined && after !== null ? after : identity); return pre;
    }
    if (before !== undefined && before !== null) { block("del", "-", before); }
    if (after !== undefined && after !== null) { block("add", "+", after); }
    if (!pre.childNodes.length) { block("ctx", " ", identity); }
    return pre;
  }

  function detailPanel(f) {
    var d = f.detail || {};
    var panel = el("div", "detail");

    var left = el("div", {}, [
      el("h4", { text: "identity" }),
      el("pre", { cls: "diff", text: pretty(d.identity !== undefined ? d.identity : {}) })
    ]);
    panel.appendChild(left);

    panel.appendChild(el("div", {}, [
      el("h4", { text: "context" }),
      kv([
        ["finding_id", f.finding_id],
        ["fingerprint", f.fingerprint],
        ["platform", f.platform + " / " + f.category],
        ["first_seen", f.first_seen + (f.new_this_run ? "  (new this run)" : "")],
        ["caught by", (f.lens_labels || []).join(", ") || "—"],
        ["hosts", f.host_scope],
        f.prevalence_pct ? ["fleet prevalence", f.prevalence_pct] : null,
        f.suppressed ? ["suppressed by", f.suppressed_by || "(allowlist)"] : null
      ])
    ]));

    var change = el("div", "full", [el("h4", { text: "change (" + f.change_type + ")" }), diffBlock(f)]);
    panel.appendChild(change);

    if (d.per_host && Object.keys(d.per_host).length) {
      var rows = el("tbody");
      Object.keys(d.per_host).sort().forEach(function (host) {
        rows.appendChild(el("tr", {}, [
          el("td", { cls: "mono nowrap", text: host }),
          el("td", { cls: "mono", text: compact(d.per_host[host]) })
        ]));
      });
      panel.appendChild(el("div", "full", [
        el("h4", { text: "per-host values (the merged hosts diverge)" }),
        el("div", "scroll-x", [el("table", {}, [rows])])
      ]));
    }

    if (f.note) {
      panel.appendChild(el("div", "full", [el("h4", { text: "note" }), el("p", { text: f.note })]));
    }
    if (f.hosts.length) {
      panel.appendChild(el("div", "full", [
        el("h4", { text: "affected hosts (" + f.hosts.length + ")" }),
        el("p", { cls: "mono hosts", text: f.hosts.join(", ") })
      ]));
    }
    return panel;
  }

  /* ---------------------------------------------------------------- findings view */

  function matches(f) {
    if (!activeSeverities().has(f.severity)) { return false; }
    if (filters.suppressed === "hide" && f.suppressed) { return false; }
    if (filters.suppressed === "only" && !f.suppressed) { return false; }
    if (filters.host && f.hosts.indexOf(filters.host) === -1) { return false; }
    if (filters.category && f.category !== filters.category) { return false; }
    if (filters.q) {
      /* `fingerprint` is in the haystack on purpose: it is the identity the report and the
         matrix both print, so an analyst can paste one straight out of either and land on
         the finding. `headline` carries the friendly coverage-gap wording. */
      var hay = [f.rule, f.identity_str, f.category, f.change_type, f.platform,
        f.before_str, f.after_str, f.note, f.hosts.join(" "), f.finding_id, f.fingerprint,
        f.headline].join(" ").toLowerCase();
      if (hay.indexOf(filters.q.toLowerCase()) === -1) { return false; }
    }
    return true;
  }

  /* Filters deliberately survive a run/engagement switch — an analyst comparing two runs
     wants to keep their lens. But a host or category that does not exist in the NEW run
     would silently hide everything while the dropdown still reads "all hosts" (the select
     falls back to "" when its value is not an option). Drop whatever no longer applies. */
  function reconcileFilters(data) {
    if (filters.host && data.hosts.indexOf(filters.host) === -1) { filters.host = ""; }
    if (filters.category && data.categories.indexOf(filters.category) === -1) {
      filters.category = "";
    }
    if (filters.expanded && !data.findings.some(function (f) {
      return f.finding_id === filters.expanded;
    })) { filters.expanded = null; }
  }

  function sortValue(f) {
    switch (filters.sortKey) {
      case "rule": return f.rule;
      case "category": return f.category + "/" + f.change_type;
      case "hosts": return f.host_count;
      case "first_seen": return f.first_seen;
      default: return null;
    }
  }

  function sortFindings(list) {
    return list.slice().sort(function (a, b) {
      if (filters.sortKey === "severity") {
        var d = severityRank(a.severity) - severityRank(b.severity);
        if (d) { return d * filters.sortDir; }
        return (a.fingerprint < b.fingerprint ? -1 : a.fingerprint > b.fingerprint ? 1 : 0)
          * filters.sortDir;
      }
      var av = sortValue(a), bv = sortValue(b);
      if (av < bv) { return -1 * filters.sortDir; }
      if (av > bv) { return 1 * filters.sortDir; }
      return severityRank(a.severity) - severityRank(b.severity);
    });
  }

  DW.views.findings = { render: function (root) {
    root.appendChild(el("h1", { text: "Findings" }));
    if (!state.engagement) { root.appendChild(empty("Select an engagement")); return; }
    if (!state.runData) {
      root.appendChild(empty("No run selected",
        "This engagement has no findings files yet. Run collect (which diffs and reports "
        + "automatically), or diff an existing pair of snapshots."));
      return;
    }

    var data = state.runData;
    reconcileFilters(data);
    root.appendChild(el("p", "subtitle", [
      "run ", el("span", { cls: "mono", text: data.run_id }),
      data.prev_run_id ? " · previous " : "",
      data.prev_run_id ? el("span", { cls: "mono", text: data.prev_run_id }) : "",
      " · ", String(data.totals.active), " active, ", String(data.totals.suppressed),
      " suppressed"
    ]));

    if (!data.findings.length) {
      root.appendChild(empty("No findings in this run",
        "A clean run is a result too — the report renders the same way."));
      return;
    }

    /* --- toolbar ---------------------------------------------------------- */
    var toolbar = el("div", "toolbar");
    var chips = el("div", "chips");
    state.severities.forEach(function (sev) {
      var count = data.findings.filter(function (f) { return f.severity === sev; }).length;
      var chip = el("button", {
        cls: "chip " + sev, text: sev + " " + count,
        attrs: { type: "button", "aria-pressed": activeSeverities().has(sev) ? "true" : "false" },
        on: { click: function () {
          var set = activeSeverities();
          if (set.has(sev)) { set.delete(sev); } else { set.add(sev); }
          if (!set.size) { state.severities.forEach(function (s) { set.add(s); }); }
          DW.renderView();
        } }
      });
      chips.appendChild(chip);
    });
    toolbar.appendChild(el("label", { cls: "field" }, [
      el("span", "field-label", ["severity"]), chips]));

    var search = el("input", {
      attrs: { type: "text", "data-search": "1", placeholder: "search rule, identity, detail…",
        "aria-label": "Search findings" },
      props: { value: filters.q },
      on: { input: function (ev) { filters.q = ev.target.value; redraw(); } }
    });
    toolbar.appendChild(el("label", { cls: "field grow" }, [
      el("span", "field-label", ["search"]), search]));

    var hostSel = el("select", { attrs: { "aria-label": "Host" },
      on: { change: function (ev) { filters.host = ev.target.value; redraw(); } } },
      [el("option", { text: "all hosts", attrs: { value: "" } })].concat(
        data.hosts.map(function (h) { return el("option", { text: h, attrs: { value: h } }); })));
    hostSel.value = filters.host;
    toolbar.appendChild(el("label", { cls: "field" }, [
      el("span", "field-label", ["host"]), hostSel]));

    var catSel = el("select", { attrs: { "aria-label": "Category" },
      on: { change: function (ev) { filters.category = ev.target.value; redraw(); } } },
      [el("option", { text: "all categories", attrs: { value: "" } })].concat(
        data.categories.map(function (c) {
          return el("option", { text: c, attrs: { value: c } }); })));
    catSel.value = filters.category;
    toolbar.appendChild(el("label", { cls: "field" }, [
      el("span", "field-label", ["category"]), catSel]));

    var suppSel = el("select", { attrs: { "aria-label": "Suppressed" },
      on: { change: function (ev) { filters.suppressed = ev.target.value; redraw(); } } }, [
      el("option", { text: "show suppressed", attrs: { value: "all" } }),
      el("option", { text: "hide suppressed", attrs: { value: "hide" } }),
      el("option", { text: "only suppressed", attrs: { value: "only" } })
    ]);
    suppSel.value = filters.suppressed;
    toolbar.appendChild(el("label", { cls: "field" }, [
      el("span", "field-label", ["suppressed"]), suppSel]));

    toolbar.appendChild(el("button", { cls: "btn", text: "reset", attrs: { type: "button" },
      on: { click: function () {
        filters.sev = new Set(state.severities);
        filters.host = ""; filters.category = ""; filters.q = ""; filters.suppressed = "all";
        filters.expanded = null;
        DW.renderView();
      } } }));
    root.appendChild(toolbar);

    var note = el("p", "count-note");
    root.appendChild(note);
    var wrap = el("div", "scroll-x");
    root.appendChild(wrap);

    function header(label, key, cls) {
      if (!key) { return el("th", { cls: cls || "", text: label }); }
      var arrow = filters.sortKey === key ? (filters.sortDir === 1 ? " ↑" : " ↓") : "";
      return el("th", {
        cls: "sortable " + (cls || ""), text: label + arrow,
        attrs: { title: "sort by " + label },
        on: { click: function () {
          if (filters.sortKey === key) { filters.sortDir *= -1; }
          else { filters.sortKey = key; filters.sortDir = 1; }
          DW.renderView();
        } }
      });
    }

    function redraw() {
      var shown = sortFindings(state.runData.findings.filter(matches));
      clear(note);
      note.appendChild(document.createTextNode(
        shown.length + " of " + state.runData.findings.length + " finding(s)"
        + (filters.host ? " on " + filters.host : "")));
      clear(wrap);
      if (!shown.length) {
        wrap.appendChild(empty("Nothing matches these filters",
          "Widen the severity chips or clear the search box."));
        return;
      }
      var tbody = el("tbody");
      var table = el("table", {}, [
        el("thead", {}, [el("tr", {}, [
          header("sev", "severity"), header("rule", "rule"),
          header("category / change", "category"), header("hosts", "hosts", "num"),
          header("first seen", "first_seen"), header("lenses"), header("")
        ])]),
        tbody
      ]);
      shown.forEach(function (f) { appendRow(tbody, f); });
      wrap.appendChild(table);
    }

    function appendRow(tbody, f) {
      var hostText = f.hosts.length > 3
        ? f.hosts.slice(0, 3).join(", ") + " +" + (f.hosts.length - 3) + " more"
        : (f.hosts.join(", ") || "—");
      var flags = el("td", "nowrap");
      if (f.new_this_run) { flags.appendChild(el("span", { cls: "tag new", text: "NEW" })); }
      if (f.suppressed) { flags.appendChild(el("span", { cls: "tag supp", text: "suppressed" })); }

      var row = el("tr", {
        cls: "row-main" + (f.suppressed ? " suppressed" : "")
          + (filters.expanded === f.finding_id ? " selected" : ""),
        attrs: { tabindex: "0" },
        on: {
          click: function () { toggle(f, row); },
          keydown: function (ev) {
            if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(f, row); }
          }
        }
      }, [
        el("td", {}, [sevBadge(f.severity)]),
        el("td", { cls: "rule", text: f.rule, attrs: { title: f.identity_str } }),
        /* Coverage gaps are the one row type where "meta · coverage_gap" says nothing;
           report_gen already computed the sentence the report prints, so show that. */
        f.change_type === "coverage_gap" && f.headline
          ? el("td", {}, [el("span", { text: f.headline })])
          : el("td", {}, [el("span", { text: f.category }),
            el("span", { cls: "dim", text: " · " + f.change_type })]),
        el("td", { cls: "num nowrap", text: String(f.host_count), attrs: { title: hostText } }),
        el("td", { cls: "mono nowrap dim", text: f.first_seen }),
        el("td", { cls: "dim", text: (f.comparison || []).join(", ") }),
        flags
      ]);
      tbody.appendChild(row);

      if (filters.expanded === f.finding_id) {
        tbody.appendChild(el("tr", "detail-row", [
          el("td", { attrs: { colspan: 7 } }, [detailPanel(f)])]));
      }
    }

    function toggle(f) {
      filters.expanded = filters.expanded === f.finding_id ? null : f.finding_id;
      redraw();
    }

    /* Guarded because the handler outlives this render: app.js clears it on a view change,
       but a run switch can still land here with the table already torn down. */
    DW.onEscape = function () {
      if (filters.expanded && state.runData) { filters.expanded = null; redraw(); }
    };
    redraw();
  } };

  /* ---------------------------------------------------------------- fleet matrix */

  DW.views.matrix = { render: function (root) {
    root.appendChild(el("h1", { text: "Fleet matrix" }));
    root.appendChild(el("p", "subtitle", ["Findings × hosts — the direct answer to "
      + "“what machines have what differences” (design §7 item 4). Same grid the "
      + "report renders, from fleet_stats.build_matrix."]));
    if (!state.engagement) { root.appendChild(empty("Select an engagement")); return; }
    if (!state.runData) { root.appendChild(empty("No run selected")); return; }

    var matrix = state.runData.matrix;
    if (!matrix.rows.length || !matrix.hosts.length) {
      root.appendChild(empty("Nothing to plot",
        "The matrix needs at least one active finding and one host in this run."));
      return;
    }

    var q = { value: "" };
    var searchBox = el("input", {
      attrs: { type: "text", "data-search": "1", placeholder: "filter rows by rule / category…",
        "aria-label": "Filter matrix rows" },
      on: { input: function (ev) { q.value = ev.target.value.toLowerCase(); draw(); } }
    });
    root.appendChild(el("div", "toolbar", [
      el("label", { cls: "field grow" }, [el("span", "field-label", ["filter"]), searchBox]),
      el("span", { cls: "hint", text: matrix.rows.length + " row(s) × "
        + matrix.hosts.length + " host(s) · click a row to open it in Findings" })
    ]));

    var legend = el("div", "legend");
    state.severities.forEach(function (sev) {
      legend.appendChild(el("span", {}, [el("span", { cls: "cell-mark " + sev }), sev]));
    });
    legend.appendChild(el("span", {}, [el("span", "cell-empty"), "not affected"]));
    root.appendChild(legend);

    var wrap = el("div", "matrix-wrap");
    root.appendChild(wrap);

    function draw() {
      clear(wrap);
      var head = el("tr", {}, [el("th", { cls: "corner", text: "finding" })].concat(
        matrix.hosts.map(function (h) {
          return el("th", { cls: "hostcol", text: h, attrs: { title: h } });
        })));
      var tbody = el("tbody");
      var shown = 0;
      matrix.rows.forEach(function (row) {
        var hay = (row.rule + " " + row.category + " " + row.change_type + " "
          + row.severity).toLowerCase();
        if (q.value && hay.indexOf(q.value) === -1) { return; }
        shown += 1;
        var label = el("td", {
          cls: "rowhead", attrs: { title: row.rule + " (" + row.present_count + " host(s))" },
          on: { click: function () {
            /* Search by finding_id, not fingerprint: both are in the haystack now, but the
               id is what the Findings table and the report print, so the analyst can read
               the search box and see why the list narrowed. */
            filters.q = row.finding_id || row.fingerprint || "";
            filters.expanded = row.finding_id;
            filters.sev = new Set(state.severities);
            filters.host = ""; filters.category = ""; filters.suppressed = "all";
            DW.go("findings");
          } }
        }, [
          sevBadge(row.severity), " ",
          el("span", { cls: "rule", text: row.rule }),
          el("span", { cls: "dim", text: "  " + row.category + " · " + row.change_type })
        ]);
        var tr = el("tr", {}, [label].concat(matrix.hosts.map(function (host, i) {
          var on = row.cells_ordered ? row.cells_ordered[i] : row.cells[host];
          return el("td", { cls: "cell", attrs: { title: host + (on ? " — affected" : "") } },
            [el("span", { cls: on ? "cell-mark " + sevClass(row.severity) : "cell-empty" })]);
        })));
        tbody.appendChild(tr);
      });
      if (!shown) {
        wrap.appendChild(empty("No rows match that filter"));
        return;
      }
      wrap.appendChild(el("table", "matrix", [el("thead", {}, [head]), tbody]));
    }
    draw();
  } };
}());
