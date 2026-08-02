/* driftwatch operator console — scope.yml setup wizard.
 *
 * scope.yml is the authorization rail (design §15.2), so this form fails closed the same way
 * the rest of the tool does: it refuses to submit without `authorized_by`, refuses an empty
 * `in_scope`, and never offers a "just allow everything" shortcut. Validation here is a
 * convenience — scripts/gui_server.py re-validates everything server-side and round-trips the
 * generated YAML through scope_gate before a byte is written.
 */
(function () {
  "use strict";

  var DW = window.DW;
  var el = DW.el, clear = DW.clear, empty = DW.empty;
  var state = DW.state;

  var form = null;         // survives view switches within a session
  var preview = { yaml: "", errors: [], saved: null };

  function blankForm() {
    return {
      mode: "edit", engagement: "", client: "", authorized_by: "",
      in_scope: [], deny: [], oob: [],
      settings: {
        hash_policy: "tiered", collector_account: "svc-driftwatch",
        outlier_max_prevalence: 0.05, outlier_min_group: 20
      }
    };
  }

  /* ---------------------------------------------------------------- validators */

  var HOSTNAME_RE = /^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
  var GROUP_RE = /^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$/;
  var ENGAGEMENT_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

  function isIPv4(v) {
    var parts = String(v).split(".");
    if (parts.length !== 4) { return false; }
    return parts.every(function (p) {
      return /^\d{1,3}$/.test(p) && Number(p) <= 255 && (p === "0" || p[0] !== "0");
    });
  }
  function isIPv6(v) { return /^[0-9A-Fa-f:]+(\.[0-9.]+)?$/.test(v) && v.indexOf(":") !== -1; }
  function isIP(v) { return isIPv4(v) || isIPv6(v); }
  function isCIDR(v) {
    var bits = String(v).split("/");
    if (bits.length !== 2 || !/^\d{1,3}$/.test(bits[1])) { return false; }
    var len = Number(bits[1]);
    if (isIPv4(bits[0])) { return len <= 32; }
    return isIPv6(bits[0]) && len <= 128;
  }
  function groupsOf(raw) {
    return String(raw || "").split(",").map(function (g) { return g.trim(); })
      .filter(function (g) { return g; });
  }

  function validate() {
    var errs = [];
    if (!ENGAGEMENT_RE.test(form.engagement)) {
      errs.push("engagement id must look like acme-2026-07 (letters, digits, . _ -)");
    }
    if (!form.client.trim()) { errs.push("client is required"); }
    if (!form.authorized_by.trim()) {
      errs.push("authorized_by is REQUIRED — who authorized this, and the SOW reference. "
        + "No run proceeds without it (design §15.2).");
    }
    if (!form.in_scope.length) {
      errs.push("in_scope is empty — an empty scope authorizes nothing. Add at least one "
        + "authorized range or host; the wizard will not write a permissive file.");
    }
    form.in_scope.forEach(function (entry, i) {
      var where = "in_scope[" + (i + 1) + "]";
      if (entry.kind === "cidr") {
        if (!isCIDR(entry.cidr)) { errs.push(where + ": '" + entry.cidr + "' is not a CIDR "
          + "(e.g. 10.10.0.0/16)"); }
      } else {
        if (!HOSTNAME_RE.test(entry.host || "")) {
          errs.push(where + ": '" + (entry.host || "") + "' is not a valid hostname/FQDN");
        }
        if (!isIP(entry.ip || "")) {
          errs.push(where + ": '" + (entry.ip || "") + "' is not an IP — the scope gate keys "
            + "off IPs and fails closed without one");
        }
      }
      var groups = groupsOf(entry.groups);
      if (!groups.length) { errs.push(where + ": at least one ansible group is required"); }
      groups.forEach(function (g) {
        if (!GROUP_RE.test(g)) { errs.push(where + ": '" + g + "' is not a valid group name"); }
      });
    });
    form.deny.forEach(function (c, i) {
      if (c.trim() && !isCIDR(c.trim())) { errs.push("deny[" + (i + 1) + "]: '" + c + "' is not a CIDR"); }
    });
    form.oob.forEach(function (c, i) {
      if (c.trim() && !isCIDR(c.trim())) { errs.push("oob_subnets[" + (i + 1) + "]: '" + c + "' is not a CIDR"); }
    });
    if (!form.settings.collector_account.trim()) { errs.push("collector_account is required"); }
    return errs;
  }

  function payload() {
    return {
      engagement: form.engagement.trim(),
      client: form.client.trim(),
      authorized_by: form.authorized_by.trim(),
      in_scope: form.in_scope.map(function (e) {
        return e.kind === "cidr"
          ? { cidr: e.cidr.trim(), groups: groupsOf(e.groups) }
          : { host: (e.host || "").trim(), ip: (e.ip || "").trim(), groups: groupsOf(e.groups) };
      }),
      deny: form.deny.map(function (c) { return c.trim(); }).filter(Boolean),
      oob_subnets: form.oob.map(function (c) { return c.trim(); }).filter(Boolean),
      settings: {
        hash_policy: form.settings.hash_policy,
        collector_account: form.settings.collector_account.trim(),
        outlier_max_prevalence: Number(form.settings.outlier_max_prevalence),
        outlier_min_group: Number(form.settings.outlier_min_group)
      }
    };
  }

  /* ---------------------------------------------------------------- field helpers */

  function field(label, value, onInput, opts) {
    opts = opts || {};
    var input = el("input", {
      attrs: { type: opts.type || "text", placeholder: opts.placeholder || "" },
      props: { value: value === undefined || value === null ? "" : String(value) },
      on: { input: function (ev) { onInput(ev.target.value); staleness(); } }
    });
    return el("label", { cls: "f " + (opts.cls || "") }, [
      el("span", { text: label }), input,
      opts.hint ? el("span", { cls: "hint", text: opts.hint }) : null
    ]);
  }

  function select(label, value, options, onChange) {
    var sel = el("select", { on: { change: function (ev) { onChange(ev.target.value); staleness(); } } },
      options.map(function (opt) { return el("option", { text: opt, attrs: { value: opt } }); }));
    sel.value = value;
    return el("label", "f", [el("span", { text: label }), sel]);
  }

  var staleNode = null;
  var errBoxNode = null;      // live error list, refreshed on every keystroke
  var saveBtnNode = null;     // its disabled state must track the errors, not the last render

  /* Re-run validation against the current form and repaint the error list + Save button
     IN PLACE. This has to be surgical rather than a DW.renderView(): a full re-render on
     every keystroke would rebuild the inputs and throw away the caret. Without it the
     wizard reads as broken — the analyst fills in every field correctly and Save stays
     greyed out under a list of errors they already fixed, because both were computed once
     at render time and never looked at again. */
  function revalidate() {
    var errs = validate();
    if (errBoxNode) {
      clear(errBoxNode);
      if (errs.length) {
        var ul = el("ul", "err-list");
        errs.forEach(function (e) { ul.appendChild(el("li", { text: e })); });
        errBoxNode.appendChild(ul);
      }
    }
    if (saveBtnNode) { saveBtnNode.disabled = errs.length > 0; }
    return errs;
  }

  function staleness() {
    if (preview.yaml || preview.saved) {
      preview.yaml = ""; preview.saved = null; preview.errors = [];
      if (staleNode) { clear(staleNode); staleNode.appendChild(
        el("p", { cls: "hint", text: "form changed — preview again to see the YAML" })); }
    }
    revalidate();
  }

  /* ---------------------------------------------------------------- view */

  DW.views.setup = { render: function (root) {
    if (!form) {
      form = blankForm();
      form.engagement = state.engagement || "";
      /* With no engagement volume yet there is nothing to edit — the only useful path is
         creating one, so start there rather than on a mode that can only fail. */
      form.mode = state.engagement ? "edit" : "new";
    }
    root.appendChild(el("h1", { text: "Setup wizard" }));
    root.appendChild(el("p", "subtitle", ["Builds ",
      el("span", { cls: "path", text: "engagements/<id>/scope.yml" }),
      " — the authorization rail. Fill it in from the SIGNED authorization document, not "
      + "from what happens to be reachable (design §15.2)."]));

    /* --- mode ------------------------------------------------------------- */
    var modeRow = el("div", "chips");
    [["edit", "edit the selected engagement"], ["new", "create a NEW engagement volume"]]
      .forEach(function (pair) {
        modeRow.appendChild(el("button", {
          cls: "chip plain", text: pair[1],
          attrs: { type: "button", "aria-pressed": form.mode === pair[0] ? "true" : "false" },
          on: { click: function () {
            form.mode = pair[0];
            if (pair[0] === "edit" && state.engagement) { form.engagement = state.engagement; }
            preview.saved = null; preview.yaml = "";
            DW.renderView();
          } }
        }));
      });
    root.appendChild(el("div", "form-block", [
      el("h3", { text: "mode" }), modeRow,
      form.mode === "edit" && state.engagement
        ? el("div", "btn-row", [el("button", {
          cls: "btn small", text: "load current scope.yml", attrs: { type: "button" },
          on: { click: loadCurrent } })])
        : null,
      form.mode === "new"
        ? el("p", { cls: "hint", text: "Creates the engagement volume (inventory/, snapshots/, "
          + "findings/, reports/, vault/ 0700, audit.log) and writes scope.yml into it. No "
          + "credentials are created — filling the vault stays a deliberate operator act. "
          + "Note: `driftwatch new-engagement` additionally initialises the per-engagement git "
          + "history for tamper-evidence (design §5); this wizard does not." })
        : null
    ]));

    /* --- identity --------------------------------------------------------- */
    root.appendChild(el("div", "form-block", [
      el("h3", { text: "engagement" }),
      el("div", "form-grid", [
        field("engagement id", form.engagement, function (v) { form.engagement = v; },
          { placeholder: "acme-2026-07", hint: "<client>-<yyyy>-<mm>; also the volume dir name" }),
        field("client", form.client, function (v) { form.client = v; },
          { placeholder: "ACME Corp" }),
        el("div", "full", [field("authorized_by  (REQUIRED)", form.authorized_by,
          function (v) { form.authorized_by = v; },
          { placeholder: "J. Doe, CISO (signed SOW 2026-07-01)",
            hint: "Free text naming who authorized this and the reference. The wizard refuses "
              + "to save while this is blank." })])
      ])
    ]));

    /* --- in_scope --------------------------------------------------------- */
    var entries = el("div");
    form.in_scope.forEach(function (entry, idx) { entries.appendChild(entryRow(entry, idx)); });
    root.appendChild(el("div", "form-block", [
      el("h3", { text: "in_scope — the allow-list" }),
      el("p", { cls: "hint", text: "The ONLY source of authorized targets. A bare CIDR "
        + "authorizes a range but creates no addressable host: hosts discovered inside it must "
        + "be added explicitly before they are ever touched (discovery ≠ access)." }),
      entries,
      form.in_scope.length ? null : el("p", { cls: "err",
        text: "empty — this engagement would authorize nothing" }),
      el("div", "btn-row", [
        el("button", { cls: "btn", text: "+ range (CIDR)", attrs: { type: "button" },
          on: { click: function () {
            form.in_scope.push({ kind: "cidr", cidr: "", groups: "linux" });
            staleness(); DW.renderView(); } } }),
        el("button", { cls: "btn", text: "+ host", attrs: { type: "button" },
          on: { click: function () {
            form.in_scope.push({ kind: "host", host: "", ip: "", groups: "windows" });
            staleness(); DW.renderView(); } } })
      ])
    ]));

    /* --- deny / oob ------------------------------------------------------- */
    root.appendChild(el("div", "form-block", [
      el("h3", { text: "deny — never touch (wins over in_scope)" }),
      listEditor(form.deny, "10.10.99.0/24"),
      el("h3", { text: "oob_subnets — out-of-band management networks" }),
      el("p", { cls: "hint", text: "Anything NOT listed here is assumed IN-BAND (design §13.5): "
        + "the path you manage a device over may be the path a change severs. Leave empty if "
        + "there is no separate management network." }),
      listEditor(form.oob, "192.168.99.0/24")
    ]));

    /* --- settings --------------------------------------------------------- */
    var s = form.settings;
    root.appendChild(el("div", "form-block", [
      el("h3", { text: "settings" }),
      el("div", "form-grid", [
        select("hash_policy", s.hash_policy,
          state.hashPolicies.length ? state.hashPolicies : ["full", "tiered", "servers_only"],
          function (v) { s.hash_policy = v; }),
        field("collector_account", s.collector_account, function (v) { s.collector_account = v; },
          { hint: "tagged collector_self by the normalizer" }),
        field("outlier_max_prevalence", s.outlier_max_prevalence,
          function (v) { s.outlier_max_prevalence = v; },
          { hint: "item on ≤ this fraction of a group" }),
        field("outlier_min_group", s.outlier_min_group, function (v) { s.outlier_min_group = v; },
          { hint: "…of a group with ≥ this many members" })
      ])
    ]));

    /* --- validate / preview / save ---------------------------------------- */
    errBoxNode = el("div");
    root.appendChild(errBoxNode);

    staleNode = el("div");
    saveBtnNode = el("button", {
      cls: "btn primary", text: form.mode === "new" ? "Create engagement + save scope.yml"
        : "Save scope.yml",
      attrs: { type: "button" },
      on: { click: doSave }
    });
    root.appendChild(el("div", "btn-row", [
      el("button", { cls: "btn", text: "Preview YAML", attrs: { type: "button" },
        on: { click: doPreview } }),
      saveBtnNode
    ]));
    root.appendChild(staleNode);
    revalidate();   // paints the error list and the Save button for the current form

    if (preview.errors.length) {
      var sul = el("ul", "err-list");
      preview.errors.forEach(function (e) { sul.appendChild(el("li", { text: e })); });
      root.appendChild(el("div", {}, [el("h3", { text: "server refused" }), sul]));
    }
    if (preview.yaml) {
      root.appendChild(el("h3", { text: "generated scope.yml — review before saving" }));
      root.appendChild(el("pre", { cls: "raw", text: preview.yaml }));
    }
    if (preview.saved) {
      root.appendChild(el("div", "warnbox", [
        el("h4", { text: "saved" }),
        el("p", {}, [DW.pathLine(preview.saved.path)]),
        el("p", { cls: "hint", text: "Inventory generation is what turns scope.yml into "
          + "addressable hosts — until then nothing is targetable." }),
        el("div", "btn-row", [
          el("button", { cls: "btn primary", text: "Generate inventory now",
            attrs: { type: "button" },
            on: { click: function () {
              DW.confirmAction("scope-generate").then(function (a) {
                if (a) { DW.runAction("scope-generate"); }
              });
            } } })
        ])
      ]));
    }

    function loadCurrent() {
      DW.apiGet("/api/scope", { engagement: state.engagement }).then(function (info) {
        if (!info.exists || !info.parses) {
          DW.showError(info.exists ? "scope.yml does not parse: " + info.error
            : "this engagement has no scope.yml yet");
          return;
        }
        var d = info.data;
        form.mode = "edit";
        form.engagement = d.engagement || state.engagement;
        form.client = d.client || "";
        form.authorized_by = d.authorized_by || "";
        form.in_scope = (d.in_scope || []).map(function (e) {
          return e.cidr && !e.host
            ? { kind: "cidr", cidr: e.cidr, groups: (e.groups || []).join(", ") }
            : { kind: "host", host: e.host || "", ip: e.ip || "",
                groups: (e.groups || []).join(", ") };
        });
        form.deny = (d.deny || []).map(function (e) { return e.cidr || ""; });
        form.oob = (d.oob_subnets || []).slice();
        var ds = d.settings || {};
        form.settings = {
          hash_policy: ds.hash_policy || "tiered",
          collector_account: ds.collector_account || "svc-driftwatch",
          outlier_max_prevalence: ds.outlier_max_prevalence === undefined
            ? 0.05 : ds.outlier_max_prevalence,
          outlier_min_group: ds.outlier_min_group === undefined ? 20 : ds.outlier_min_group
        };
        preview.yaml = ""; preview.saved = null; preview.errors = [];
        DW.renderView();
      }, function (err) { DW.showError("scope: " + err.message); });
    }

    function doPreview() {
      DW.apiPost("/api/scope/preview", { form: payload() }).then(function (res) {
        preview.yaml = res.yaml || ""; preview.errors = res.errors || []; preview.saved = null;
        DW.renderView();
      }, function (err) { DW.showError("preview: " + err.message); });
    }

    function doSave() {
      var body = [
        el("p", { text: form.mode === "new"
          ? "This creates a new engagement volume and writes its authorization record."
          : "This overwrites the engagement's authorization record." }),
        DW.kv([
          ["engagement", form.engagement],
          ["client", form.client],
          ["authorized_by", form.authorized_by],
          ["in_scope", form.in_scope.length + " entr(ies)"],
          ["deny", form.deny.filter(Boolean).length + " CIDR(s)"],
          ["oob_subnets", form.oob.filter(Boolean).length
            + (form.oob.filter(Boolean).length ? "" : " — every device treated as in-band")]
        ])
      ];
      DW.confirmDialog({
        title: form.mode === "new" ? "Create " + form.engagement + "?" : "Overwrite scope.yml?",
        body: body, confirmLabel: "write scope.yml", danger: form.mode !== "new"
      }).then(function (answer) {
        if (!answer) { return; }
        return DW.apiPost("/api/scope/save", {
          form: payload(), mode: form.mode, overwrite: true
        }).then(function (res) {
          preview.saved = res; preview.yaml = res.yaml; preview.errors = [];
          return DW.refreshEngagements()
            .then(function () { return DW.loadEngagement(res.engagement); })
            .then(function () { DW.go("setup"); });
        }, function (err) { DW.showError("save refused: " + err.message); });
      });
    }
  } };

  function entryRow(entry, idx) {
    var row = el("div", "entry-row");
    row.appendChild(select("kind", entry.kind === "cidr" ? "range (CIDR)" : "host",
      ["range (CIDR)", "host"], function (v) {
        entry.kind = v === "host" ? "host" : "cidr"; DW.renderView();
      }));
    if (entry.kind === "cidr") {
      row.appendChild(field("cidr", entry.cidr, function (v) { entry.cidr = v; },
        { placeholder: "10.10.0.0/16", cls: "grow" }));
    } else {
      row.appendChild(field("host / FQDN", entry.host, function (v) { entry.host = v; },
        { placeholder: "dc01.acme.example" }));
      row.appendChild(field("ip", entry.ip, function (v) { entry.ip = v; },
        { placeholder: "10.10.1.5" }));
    }
    row.appendChild(field("groups (comma separated)", entry.groups,
      function (v) { entry.groups = v; }, { placeholder: "windows, win_servers" }));
    row.appendChild(el("button", {
      cls: "btn small ghost", text: "remove", attrs: { type: "button" },
      on: { click: function () {
        form.in_scope.splice(idx, 1); staleness(); DW.renderView(); } }
    }));
    return row;
  }

  function listEditor(list, placeholder) {
    var box = el("div");
    list.forEach(function (value, idx) {
      box.appendChild(el("div", "entry-row", [
        field("cidr", value, function (v) { list[idx] = v; },
          { placeholder: placeholder, cls: "grow" }),
        el("button", { cls: "btn small ghost", text: "remove", attrs: { type: "button" },
          on: { click: function () { list.splice(idx, 1); staleness(); DW.renderView(); } } })
      ]));
    });
    box.appendChild(el("div", "btn-row", [
      el("button", { cls: "btn small", text: "+ add", attrs: { type: "button" },
        on: { click: function () { list.push(""); staleness(); DW.renderView(); } } })
    ]));
    return box;
  }
}());
