// DMARC Reports: the app's pages. Everything is drawn here from the API (src/*.ts); the address bar keeps
// what's open (?domain=…, ?upload=…, ?page=…) so it can be bookmarked and the back button works.

(function () {
  "use strict";
  const main = document.getElementById("main");
  const nav = document.getElementById("nav");
  const foot = document.getElementById("foot");

  // --- Small helpers ---------------------------------------------------------------------------------

  /** Makes an element. Styles go through the CSSOM (the page's security policy blocks style="" attributes). */
  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === false || v == null) continue;
      if (k === "class") n.className = v;
      else if (k === "style") for (const [p, val] of Object.entries(v)) n.style.setProperty(p, val);
      else if (k === "html") n.innerHTML = v; // only ever our own icons
      else if (k === "href" && /^[\s\0-\x1f]*(javascript|data|vbscript):/i.test(String(v))) continue;
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? "" : v);
    }
    for (const k of kids.flat(Infinity)) if (k != null && k !== false) n.append(k.nodeType ? k : String(k));
    return n;
  }

  const P = 'fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"';
  const ICONS = {
    domains: `<path d="M3 10h14M10 3c2.2 2.1 3 4.6 3 7s-.8 4.9-3 7c-2.2-2.1-3-4.6-3-7s.8-4.9 3-7z"/><circle cx="10" cy="10" r="7"/>`,
    upload: `<path d="M10 13V3.5M6 7l4-4 4 4"/><path d="M3.5 13v2.5a1 1 0 0 0 1 1h11a1 1 0 0 0 1-1V13"/>`,
    settings: `<circle cx="10" cy="10" r="2.6"/><path d="M10 2.5v2M10 15.5v2M2.5 10h2M15.5 10h2M4.7 4.7l1.4 1.4M13.9 13.9l1.4 1.4M4.7 15.3l1.4-1.4M13.9 6.1l1.4-1.4"/>`,
    out: `<path d="M8 4H4.5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1H8"/><path d="M12 6.5 15.5 10 12 13.5M15.5 10H7.5"/>`,
    in: `<path d="M12 4h3.5a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H12"/><path d="M8 6.5 11.5 10 8 13.5M11.5 10H3.5"/>`,
    plus: `<path d="M10 4v12M4 10h12"/>`,
    back: `<path d="M12 4 6 10l6 6"/>`,
    check: `<path d="M4 10.5 8 14.5 16 6"/>`,
    refresh: `<path d="M16 10a6 6 0 1 1-1.8-4.3"/><path d="M16 3.5v3.5h-3.5"/>`,
    copy: `<rect x="7" y="7" width="9.5" height="9.5" rx="1.5"/><path d="M13 7V4.5a1 1 0 0 0-1-1H4.5a1 1 0 0 0-1 1V12a1 1 0 0 0 1 1H7"/>`,
    trash: `<path d="M4 6h12M8 6V4h4v2M5.5 6l.8 10h7.4l.8-10"/>`,
    share: `<circle cx="14.5" cy="5" r="2"/><circle cx="5.5" cy="10" r="2"/><circle cx="14.5" cy="15" r="2"/><path d="M7.3 9 12.7 6M7.3 11l5.4 3"/>`,
    download: `<path d="M10 3.5V13M6 9.5l4 4 4-4"/><path d="M3.5 13v2.5a1 1 0 0 0 1 1h11a1 1 0 0 0 1-1V13"/>`,
    print: `<path d="M6 7V3.5h8V7"/><rect x="3.5" y="7" width="13" height="6.5" rx="1.5"/><path d="M6 11.5h8v5H6z"/>`,
    mine: `<path d="M10 17s-6-3.7-6-8.2A3.3 3.3 0 0 1 10 7a3.3 3.3 0 0 1 6 1.8C16 13.3 10 17 10 17z"/>`,
    not: `<circle cx="10" cy="10" r="7"/><path d="M5 15 15 5"/>`,
    undo: `<path d="M5 8h7a4 4 0 0 1 0 8H8"/><path d="M8 5 5 8l3 3"/>`,
    mail: `<rect x="2.5" y="4.5" width="15" height="11" rx="2"/><path d="M3 6l7 5 7-5"/>`,
    key: `<circle cx="7" cy="12" r="3.5"/><path d="M9.5 9.5 16 3M13.5 5.5l2 2"/>`,
    save: `<path d="M4 4h9.5L16 6.5V16H4z"/><path d="M7 4v4h6V4M7 16v-5h6v5"/>`,
    rows: `<path d="M3.5 5h13M3.5 10h13M3.5 15h13"/>`,
    open: `<path d="M11 3.5h5.5V9M16.5 3.5 9 11"/><path d="M14 11.5V16a.5.5 0 0 1-.5.5h-9A.5.5 0 0 1 4 16V7a.5.5 0 0 1 .5-.5H9"/>`,
    image: `<rect x="3" y="4" width="14" height="12" rx="2"/><circle cx="7.5" cy="8.5" r="1.5"/><path d="m4 15 4.5-4.5L12 14l2-2 3 3"/>`,
    more: `<path d="M5 8l5 5 5-5"/>`,
  };
  const icon = (name) => `<svg viewBox="0 0 20 20" ${P} aria-hidden="true">${ICONS[name] || ""}</svg>`;
  /** A button with an icon. */
  function btn(name, label, attrs = {}) {
    const b = el("button", { type: "button", class: "btn", ...attrs, html: icon(name) });
    b.append(el("span", {}, label));
    return b;
  }
  /** Changes a button's words, keeping its icon. */
  const label = (b, text) => { b.querySelector("span").textContent = text; };
  function copyBtn(text) {
    const b = el("button", { type: "button", class: "copy", title: `Copy ${text}`, html: icon("copy") });
    const w = el("span", {}, "Copy");
    b.append(w);
    b.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(text); w.textContent = "Copied"; } catch { w.textContent = "Select and copy it"; }
      setTimeout(() => { w.textContent = "Copy"; }, 1600);
    });
    return b;
  }

  const plural = (n, one, many = `${one}s`) => `${Number(n).toLocaleString("en-GB")} ${Number(n) === 1 ? one : many}`;
  const pct = (n, of) => (of ? Math.floor((n / of) * 100) : 0);
  const day = (iso) => (iso ? new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" }) : "");
  const say = (box, m) => { box.textContent = m || ""; box.hidden = !m; };
  async function api(method, path, body) {
    const opts = { method, headers: {}, cache: "no-store" };
    if (body instanceof FormData) opts.body = body;
    else if (body !== undefined) { opts.headers["content-type"] = "application/json"; opts.body = JSON.stringify(body); }
    try {
      const r = await fetch(path, opts);
      const b = await r.json().catch(() => ({}));
      if (r.status === 401 && path !== "/api/me") { start(); return { ok: false, status: 401, body: b }; }
      return { ok: r.ok, status: r.status, body: b };
    } catch {
      return { ok: false, status: 0, body: { error: "Couldn't reach the app. Please check your connection and try again." } };
    }
  }
  /** Puts parts on the page, skipping any that are empty. */
  const show = (...parts) => main.replaceChildren(...parts.flat(Infinity).filter(Boolean));
  const go = (q) => history.pushState(null, "", q ? `?${q}` : location.pathname);
  const loading = (text) => show(el("div", { class: "panel center" }, el("span", { class: "spin" }), text));
  const fail = (text) => show(el("div", { class: "panel" }, el("p", {}, text)));
  const backBtn = (text, to) => el("button", { type: "button", class: "back", html: icon("back"), onclick: to }, el("span", {}, text));

  // --- Branding --------------------------------------------------------------------------------------

  let brand = { name: "DMARC Reports", colour: "#4338ca", logo: null, support: null, custom: false };
  function applyBrand(b) {
    brand = b;
    document.documentElement.style.setProperty("--brand", b.colour);
    document.title = b.name;
    document.getElementById("brand-name").textContent = b.name;
    const mark = document.getElementById("mark");
    const old = mark.querySelector("img, svg");
    if (b.logo) old.replaceWith(el("img", { src: b.logo, alt: "" }));
    else if (old.tagName === "IMG") location.reload();
    const icon = document.querySelector("link[rel=icon]");
    if (b.logo) icon.href = b.logo;
    foot.replaceChildren(...[
      b.support ? el("p", {}, "Need help? Email ", el("a", { href: `mailto:${b.support}` }, b.support), ".") : null,
      b.custom ? null : el("p", {}, "DMARC Reports is free for personal and small business use, up to 10 domains. ", el("a", { href: "https://github.com/pobren/dmarc-reports/blob/main/LICENSE", target: "_blank", rel: "noopener" }, "Licence")),
    ].filter(Boolean));
  }

  // --- Starting up: set-up, sign-in or the app -------------------------------------------------------

  let me = null;
  async function start() {
    const q = new URLSearchParams(location.search);
    const [m, b] = await Promise.all([api("GET", "/api/me"), api("GET", "/api/brand")]);
    if (b.ok) applyBrand(b.body);
    if (q.get("share")) return shared(q.get("share"));
    if (!m.ok) return fail(m.body.error || "The app couldn't start. Please refresh the page.");
    me = m.body;
    if (q.get("setup") || !me.setUp) return setupPage(q.get("setup") || "");
    if (!me.signedIn) return signInPage();
    nav.hidden = false;
    route();
  }

  // Cloudflare Turnstile under set-up and sign-in, when the owner has switched it on (/api/me gives the site key).
  // Cloudflare's script loads only on those pages. Most people see nothing; a few are asked to tick a box.
  let tsApi = null;
  function tsLoad() {
    return tsApi || (tsApi = new Promise((ok, bad) => {
      window.drTsReady = () => ok(window.turnstile);
      const s = document.createElement("script");
      s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=drTsReady";
      s.async = true;
      s.onerror = () => { tsApi = null; bad(new Error("load")); };
      document.head.append(s);
    }));
  }
  /** Adds the widget above a form's buttons. Returns a function that gives a fresh answer ("" if none came). */
  function robotCheck(form) {
    const key = me && me.turnstile;
    if (!key) return async () => undefined;
    const box = el("div", { class: "ts-box" });
    form.querySelector(".acts").before(box);
    let id = null, token = "";
    const waiting = [];
    const hand = (v) => waiting.splice(0).forEach((f) => f(v));
    tsLoad().then((t) => { id = t.render(box, { sitekey: key, appearance: "interaction-only", callback: (v) => { token = v; hand(v); }, "expired-callback": () => { token = ""; }, "error-callback": () => hand("") }); }).catch(() => hand(""));
    return () => new Promise((ok) => {
      const give = (v) => { token = ""; if (id !== null) setTimeout(() => window.turnstile.reset(id), 0); ok(v); };
      if (token) return give(token);
      const timer = setTimeout(() => give(""), 20000);
      waiting.push((v) => { clearTimeout(timer); give(v); });
    });
  }

  function setupPage(code) {
    nav.hidden = true;
    if (me.setupLocked) {
      return show(el("div", { class: "panel narrow" },
        el("h1", {}, "Almost there"),
        el("p", {}, "Set-up is locked until the app has its own set-up code. In your Cloudflare dashboard, open ", el("b", {}, "Workers & Pages › dmarc-reports › Settings › Variables and Secrets"),
          " and give the secret ", el("code", {}, "SETUP_TOKEN"), " a long code you make up (16 characters or more). Then open:"),
        el("div", { class: "addr" }, el("code", {}, `${location.origin}/?setup=your-code`)),
        el("p", { class: "small" }, "Installed with the installer? It printed a set-up link for you: open that instead.")));
    }
    const err = el("p", { class: "err", role: "alert", hidden: true });
    const codeIn = el("input", { type: "password", autocomplete: "off", required: true, value: code });
    const pw = el("input", { type: "password", autocomplete: "new-password", required: true, minlength: "10" });
    const pw2 = el("input", { type: "password", autocomplete: "new-password", required: true });
    const rep = el("input", { type: "email", placeholder: "dmarc-reports@example.com", autocomplete: "off", value: new URLSearchParams(location.search).get("report") || "" });
    const alertTo = el("input", { type: "email", placeholder: "you@example.com", autocomplete: "email" });
    const go1 = btn("check", me.setUp ? "Set my new password" : "Finish setting up", { type: "submit" });
    const form = el("form", { class: "panel narrow" },
      el("h1", {}, me.setUp ? "Set a new password" : `Welcome to ${brand.name}`),
      el("p", { class: "lead" }, me.setUp ? "Use your set-up code to choose a new password. Everyone signed in now is signed out." : "Choose your password. Only you sign in to this app."),
      code ? null : el("label", { class: "field" }, "Set-up code", el("small", {}, "The SETUP_TOKEN you chose, or the code in the installer's link."), codeIn),
      el("label", { class: "field" }, "Password", el("small", {}, "At least 10 characters."), pw),
      el("label", { class: "field" }, "Password again", pw2),
      me.setUp ? null : [
        el("label", { class: "field" }, "Your report address", el("small", {}, "The address mail providers send reports to, routed to this app in Cloudflare Email Routing. You can add or change it later in Settings."), rep),
        el("label", { class: "field" }, "Send alerts to", el("small", {}, "Optional. Must be verified under Email Routing › Destination addresses."), alertTo),
      ],
      el("div", { class: "acts" }, go1), err);
    const robot = robotCheck(form);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      say(err, "");
      if (pw.value !== pw2.value) return say(err, "The two passwords don't match.");
      go1.disabled = true;
      const r = await api("POST", "/api/setup", { code: code || codeIn.value, password: pw.value, reportAddress: rep.value, alertTo: alertTo.value, ts: await robot() });
      go1.disabled = false;
      if (!r.ok) return say(err, r.body.error || "Something went wrong. Please try again.");
      history.replaceState(null, "", location.pathname);
      start();
    });
    show(form);
    (code ? pw : codeIn).focus();
  }

  function signInPage() {
    nav.hidden = true;
    const err = el("p", { class: "err", role: "alert", hidden: true });
    const pw = el("input", { type: "password", autocomplete: "current-password", required: true });
    const b = btn("in", "Sign in", { type: "submit" });
    const form = el("form", { class: "panel narrow" }, el("h1", {}, "Sign in"), el("label", { class: "field" }, "Password", pw), el("div", { class: "acts" }, b), err,
      el("p", { class: "small", style: { "margin-top": "16px" } }, "Forgotten it? Give SETUP_TOKEN a new code in Cloudflare (or run the installer again) and open the set-up link."));
    const robot = robotCheck(form);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      b.disabled = true;
      const r = await api("POST", "/api/sign-in", { password: pw.value, ts: await robot() });
      b.disabled = false;
      if (!r.ok) { pw.select(); return say(err, r.body.error || "Something went wrong. Please try again."); }
      start();
    });
    show(form);
    pw.focus();
  }

  // --- Navigation ------------------------------------------------------------------------------------

  const PAGES = [["domains", "Domains", ""], ["upload", "Upload", "page=upload"], ["settings", "Settings", "page=settings"]];
  function drawNav(current) {
    nav.replaceChildren(...PAGES.map(([id, text, q]) => {
      const b = btn(id, text, { class: "", "aria-current": current === id ? "page" : null, title: text, onclick: () => { go(q); route(); } });
      return b;
    }), btn("out", "Sign out", { class: "", title: "Sign out", onclick: async () => { await api("POST", "/api/sign-out"); location.href = "/"; } }));
  }

  function route() {
    const q = new URLSearchParams(location.search);
    window.scrollTo(0, 0);
    if (q.get("domain")) { drawNav("domains"); return openDomain(q.get("domain"), Number(q.get("days")) || 30, q.get("day")); }
    if (q.get("upload")) { drawNav("upload"); return showUpload(q.get("upload")); }
    if (q.get("page") === "upload") { drawNav("upload"); return uploadPage(); }
    if (q.get("page") === "settings") { drawNav("settings"); return settingsPage(); }
    drawNav("domains");
    home();
  }
  window.addEventListener("popstate", () => { if (me && me.signedIn) route(); });

  // --- Your domains ----------------------------------------------------------------------------------

  async function home() {
    loading("Loading your domains…");
    const r = await api("GET", "/api/domains");
    if (!r.ok) return fail(r.body.error || "Your domains couldn't be loaded. Please try again.");
    const { domains, uploads, address, freeDomains } = r.body;
    const err = el("p", { class: "err", role: "alert", hidden: true });
    const input = el("input", { type: "text", placeholder: "example.co.uk", "aria-label": "Domain", autocapitalize: "off", spellcheck: "false" });
    const add = btn("plus", "Add domain", { type: "submit" });
    const form = el("form", { class: "row-form" }, input, add);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!input.value.trim()) return;
      add.disabled = true;
      const x = await api("POST", "/api/domains", { domain: input.value.trim() });
      add.disabled = false;
      if (!x.ok) return say(err, x.body.error || "Something went wrong. Please try again.");
      go(`domain=${encodeURIComponent(x.body.domain)}`);
      route();
    });
    const live = (d) => !!(address && d.record && d.record.toLowerCase().includes(`mailto:${address.toLowerCase()}`));
    const list = domains.length ? el("ul", { class: "list" }, domains.map((d) => {
      const rate = pct(d.passed, d.messages);
      const [cls, chip] = !d.reports ? (live(d) ? ["passc", "Record live"] : ["warnc", "Record needed"]) : [rate >= 98 ? "passc" : "warnc", `${rate}% passed`];
      return el("li", {},
        el("div", {}, el("button", { type: "button", class: "name", onclick: () => { go(`domain=${encodeURIComponent(d.domain)}`); route(); } }, d.domain),
          el("div", { class: "meta" }, !d.reports ? (live(d) ? "Your DMARC record is set up. Reports usually arrive within a day or two." : "Add your report address to its DMARC record.")
            : `${plural(d.messages, "email")} in the last 30 days, ${rate}% passed`)),
        el("span", { class: `chip ${cls}` }, chip));
    })) : el("p", { class: "small" }, "Add your first domain above.");
    show(...[
      !address ? el("div", { class: "note warn" }, el("b", {}, "Add your report address first. "), "It's where mail providers send your reports. ",
        el("button", { type: "button", class: "back", style: { margin: "0" }, onclick: () => { go("page=settings"); route(); } }, el("span", {}, "Open Settings"))) : null,
      el("section", { class: "panel" }, el("h1", {}, "Your domains"),
        el("p", { class: "lead" }, "See every service sending email as your domains, and step safely to blocking everyone else."), form, err),
      el("section", { class: "panel" }, list,
        domains.length > freeDomains ? el("p", { class: "small", style: { "margin-top": "12px" } }, `The free licence covers up to ${freeDomains} domains. For more, see the licence at the bottom of the page.`) : null),
      uploads.length ? el("section", { class: "panel" }, el("h2", {}, "Your uploads"), el("ul", { class: "list" }, uploads.map((u) => el("li", {},
        el("div", {}, el("button", { type: "button", class: "name", onclick: () => { go(`upload=${u.id}`); route(); } }, u.domains || "Upload"),
          el("div", { class: "meta" }, `${day(u.at)}: ${plural(u.reports, "report")}, ${plural(u.messages, "email")}, ${pct(u.passed, u.messages)}% passed`)))))) : null,
    ]);
    if (!domains.length) input.focus();
  }

  // --- One domain ------------------------------------------------------------------------------------

  async function openDomain(domain, days, onDay) {
    loading(`Reading the reports for ${domain}…`);
    const r = await api("GET", `/api/domains/${encodeURIComponent(domain)}?days=${days}${onDay ? `&day=${onDay}` : ""}`);
    const back = backBtn("All your domains", () => { go(""); route(); });
    if (!r.ok) return show(back, el("div", { class: "panel" }, el("p", {}, r.body.error || "That domain couldn't be loaded.")));
    const d = r.body;
    show(back, ...[overview(d), setup(d), senders(d.analysis, d.domain), plan(d), tlsBox(d), received(d), everyRow(d), domainSettings(d)].filter(Boolean));
  }

  function record(rec) {
    return el("div", { class: "rec" }, el("dl", {},
      el("dt", {}, rec.action === "edit" ? "Change" : "Type"), el("dd", {}, el("code", {}, rec.type)),
      el("dt", {}, "Name"), el("dd", {}, el("span", {}, el("code", {}, rec.name)), copyBtn(rec.name)),
      el("dt", {}, "Content"), el("dd", {}, el("code", {}, rec.value), copyBtn(rec.value))));
  }

  function recheck(d, test) {
    const status = el("p", { class: "err", role: "status", hidden: true });
    const b = btn("refresh", "I've changed it, check again", { class: "btn quiet" });
    b.addEventListener("click", async () => {
      b.disabled = true;
      const x = await api("GET", `/api/domains/${encodeURIComponent(d.domain)}?days=${d.days}`);
      b.disabled = false;
      if (x.ok && test(x.body)) return openDomain(d.domain, d.days);
      say(status, "The change isn't showing yet. DNS changes can take a few minutes, sometimes longer. Please try again shortly.");
    });
    return [el("div", { class: "acts" }, b), status];
  }

  /** The report address and the records to add, or a tick when they're in place. */
  function setup(d) {
    if (!d.address) {
      return el("section", { class: "panel" }, el("h2", {}, "Add your report address"),
        el("p", {}, "Reports can't arrive until you've told the app which address they go to."),
        el("div", { class: "acts" }, btn("settings", "Open Settings", { onclick: () => { go("page=settings"); route(); } })));
    }
    const kids = [];
    if (d.hasUs) {
      kids.push(el("div", { class: "check passc" }, el("div", { class: "check-head" }, el("span", { class: "icon", "aria-hidden": "true" }, "✓"),
        el("div", {}, el("h4", {}, "Your DMARC record sends reports here"), el("p", { class: "sum" }, el("code", {}, d.record))))));
    } else if (d.setup) {
      kids.push(el("h2", {}, d.record ? "Add your report address to the DMARC record" : "Add a DMARC record"),
        el("p", {}, d.record ? `${d.domain} has a DMARC record, but its reports don't come here yet. Change it to the content below. Its other settings and report addresses are kept.`
          : `${d.domain} has no DMARC record yet. Add this one: it only watches, nothing is blocked, and it sends the reports here.`),
        el("ol", { class: "steps" }, d.setup.steps.map((s) => el("li", {}, s))),
        record(d.setup.record),
        d.setup.host && d.setup.host.panel ? el("p", {}, el("a", { class: "btn quiet small", href: d.setup.host.panel, target: "_blank", rel: "noopener", html: icon("open") }, el("span", {}, `Open ${d.setup.host.name}`))) : null,
        recheck(d, (x) => x.hasUs));
    }
    if (d.external && !d.external.ok) {
      kids.push(el("h3", { style: { "margin-top": "18px" } }, `Let ${d.address.split("@")[1]} take reports for ${d.domain}`),
        el("p", {}, `Your report address is on another domain, so mail providers check that domain agrees first. Add this record in the DNS for ${d.address.split("@")[1]}:`),
        record({ type: "TXT", name: d.external.name, value: d.external.value, action: "add" }),
        recheck(d, (x) => !x.external || x.external.ok));
    }
    return kids.length ? el("section", { class: "panel" }, kids) : null;
  }

  function ring(rate, text, cls) {
    return el("div", { class: `ring ${cls}`, style: { "--p": String(rate) }, role: "img", "aria-label": `${rate}% ${text}` },
      el("div", {}, el("div", {}, el("b", {}, `${rate}%`), el("small", {}, text))));
  }

  function overview(d) {
    const a = d.analysis;
    const own = a.own && a.own.messages ? a.own : null;
    const rate = own ? own.passRate : a.passRate;
    const cls = !a.messages ? "infoc" : rate >= 98 ? "passc" : rate >= 80 ? "warnc" : "failc";
    const chips = [];
    if (a.counts.fail) chips.push(el("span", { class: "chip failc" }, `${a.counts.fail} to fix`));
    if (a.counts.warn) chips.push(el("span", { class: "chip warnc" }, `${a.counts.warn} to check`));
    if (a.counts.pass) chips.push(el("span", { class: "chip passc" }, `${a.counts.pass} passing`));
    if (a.counts.info) chips.push(el("span", { class: "chip infoc" }, `${a.counts.info} not recognised`));
    const policy = a.policy ? `Your policy is p=${a.policy.p}${a.policy.pct < 100 ? ` for ${a.policy.pct}% of failing mail` : ""}: ${a.policy.p === "none" ? "failing mail is still delivered" : a.policy.p === "quarantine" ? "failing mail goes to spam" : "failing mail is refused"}.` : null;
    const top = el("div", { class: "overview" },
      a.messages ? ring(rate, own ? "of yours passed" : "passed", cls) : null,
      el("div", {}, el("h1", {}, d.domain || a.domain), el("h2", {}, a.headline),
        el("p", {}, own && a.others ? `${own.passRate}% of your ${plural(own.messages, "email")} passed DMARC. ${plural(a.others, "email")} came from servers that aren't recognised: check whether any are yours.` : a.line),
        chips.length ? el("div", { class: "chips" }, chips) : null,
        policy ? el("p", { class: "who" }, policy) : null,
        a.from ? el("p", { class: "who" }, `Reports from ${day(a.from)} to ${day(a.to)}, sent by ${a.reporters.map((x) => x.org).slice(0, 5).join(", ")}.`) : null));
    if (d.days === undefined) return el("section", { class: "panel" }, top);
    const periods = el("div", { class: "periods", role: "group", "aria-label": "Period" },
      [[7, "7 days"], [30, "30 days"], [90, "90 days"], [365, "12 months"]].map(([n, text]) => {
        const b = el("button", { type: "button", "aria-pressed": String(d.days === n && !d.day), html: icon("refresh"), onclick: () => { go(`domain=${encodeURIComponent(d.domain)}${n !== 30 ? `&days=${n}` : ""}`); route(); } });
        b.append(el("span", {}, text));
        return b;
      }));
    return el("section", { class: "panel" }, top, chart(d), d.day ? el("p", { class: "note" }, `Showing the senders on ${day(d.day)} only. `,
      el("button", { type: "button", class: "back", style: { margin: "0" }, onclick: () => { go(`domain=${encodeURIComponent(d.domain)}${d.days !== 30 ? `&days=${d.days}` : ""}`); route(); } }, el("span", {}, "Show the whole period"))) : null, periods);
  }

  /** Emails per day, passed and failed. A click shows that day's senders. */
  function chart(d) {
    const days = d.daily || [];
    if (days.length < 2) return null;
    const max = Math.max(...days.map((x) => x.messages), 1);
    const w = 600, h = 140, gap = 2, bw = Math.max(2, w / days.length - gap);
    const NS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
    svg.setAttribute("preserveAspectRatio", "none");
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", `Emails per day over the last ${d.days} days`);
    days.forEach((x, i) => {
      const xPos = i * (w / days.length);
      const passH = (x.passed / max) * (h - 4);
      const failH = ((x.messages - x.passed) / max) * (h - 4);
      const add = (cls, y, height) => { const r = document.createElementNS(NS, "rect"); r.setAttribute("class", cls); r.setAttribute("x", xPos); r.setAttribute("y", y); r.setAttribute("width", bw); r.setAttribute("height", Math.max(0, height)); svg.append(r); return r; };
      add("bar-pass", h - passH, passH);
      add("bar-fail", h - passH - failH, failH);
      const hit = add("hit", 0, h);
      const t = document.createElementNS(NS, "title");
      t.textContent = `${day(x.day)}: ${plural(x.messages, "email")}, ${pct(x.passed, x.messages)}% passed`;
      hit.append(t);
      hit.addEventListener("click", () => { go(`domain=${encodeURIComponent(d.domain)}${d.days !== 30 ? `&days=${d.days}` : ""}&day=${x.day}`); route(); });
    });
    return el("div", { class: "chart" }, svg, el("div", { class: "legend" }, el("span", {}, el("i", { style: { background: "var(--pass)" } }), "Passed"), el("span", {}, el("i", { style: { background: "var(--fail)" } }), "Failed"), el("span", {}, "Click a day to see its senders")));
  }

  const MARK = { pass: "✓", warn: "!", fail: "✕", info: "?" };
  const CLS = { pass: "passc", warn: "warnc", fail: "failc", info: "infoc" };
  function card(s, domain, onLabel) {
    const tag = s.status === "info" ? (s.key === "forwarded" ? "Forwarded" : s.label === "not" ? "Not yours" : "Not recognised: yours?") : s.status === "warn" ? "Worth a look" : s.status === "fail" ? "Needs fixing" : "Passing";
    const kids = [el("div", { class: "check-head" }, el("span", { class: "icon", "aria-hidden": "true" }, MARK[s.status]),
      el("div", {}, el("h4", {}, `${s.name} · ${plural(s.messages, "email")}`, el("span", { class: "tag" }, tag)), el("p", { class: "sum" }, s.summary)))];
    if (s.fix) {
      kids.push(el("details", { open: s.status === "fail" || s.status === "warn" }, el("summary", {}, "How to fix it"),
        el("ol", { class: "steps" }, s.fix.steps.map((x) => el("li", {}, x))),
        s.fix.link ? el("p", { class: "small" }, el("a", { href: s.fix.link.href, target: "_blank", rel: "noopener" }, s.fix.link.text)) : null));
    }
    kids.push(el("details", {}, el("summary", {}, "What this means"), el("p", { class: "why" }, s.why),
      s.found && s.found.length ? el("pre", { class: "found" }, "What the reports show:\n" + s.found.join("\n")) : null));
    if (onLabel && s.key !== "forwarded") {
      const set = (lab) => async () => { await api("POST", `/api/domains/${encodeURIComponent(domain)}/labels`, { key: s.key, label: lab }); onLabel(); };
      kids.push(el("div", { class: "labels" },
        s.label === "mine" ? btn("undo", "Marked mine: undo", { class: "btn small on", onclick: set(null) }) : btn("mine", "Mine", { class: "btn small quiet", onclick: set("mine") }),
        s.label === "not" ? btn("undo", "Marked not mine: undo", { class: "btn small on", onclick: set(null) }) : btn("not", "Not mine", { class: "btn small quiet", onclick: set("not") })));
    }
    return el("div", { class: `check ${CLS[s.status]}` }, kids);
  }

  function senders(a, domain, readOnly) {
    if (!a.senders.length) return null;
    const reload = readOnly ? null : () => openDomain(domain, Number(new URLSearchParams(location.search).get("days")) || 30, new URLSearchParams(location.search).get("day"));
    return el("section", { class: "panel" }, el("h2", {}, `Who sends email as ${a.domain}`), a.senders.map((s) => card(s, domain, reload)));
  }

  function plan(d) {
    const r = d.rollout;
    if (!r) return null;
    const STATE = { done: "Done", skipped: "Skipped", now: "You are here", next: "Next", later: "" };
    const steps = el("ol", { class: "steps-line" }, r.steps.map((s, i) => el("li", { class: s.state },
      el("span", { class: "dot", "aria-hidden": "true" }, s.state === "done" ? "✓" : s.state === "skipped" ? "–" : String(i + 1)),
      el("span", { class: "lvl" }, `Level ${i + 1} · ${s.tech}`),
      el("h4", {}, s.title, STATE[s.state] ? el("small", {}, STATE[s.state]) : null, s.date && s.state !== "done" ? el("time", { datetime: s.date }, s.state === "now" ? `since ${day(s.date)}` : `from ${day(s.date)}`) : null),
      el("p", {}, s.what),
      s.state === "next" && r.current >= 0 ? record({ type: "TXT", name: d.setup ? d.setup.record.name : "_dmarc", value: s.record, action: "edit" }) : null)));
    const status = r.current < 0 ? null
      : r.current === 4 ? el("div", { class: "ready" }, "You're at the last step. Mail that fails DMARC is refused, so set up any new service in your DNS before it sends.")
      : r.ready ? el("div", { class: "ready" }, el("b", {}, "Ready for the next step. "), "Everything that sends as you has passed for two weeks. Change your DMARC record to the content under Next.")
      : el("div", {}, el("p", { style: { margin: "12px 0 0" } }, el("b", {}, "Before the next step:")), el("ul", { class: "wait" }, r.waitingFor.map((w) => el("li", {}, w))));
    return el("section", { class: "panel" }, el("h2", {}, "DMARC enforcement level"),
      el("p", {}, "Step up slowly so your own email never gets blocked. Each step goes green only when your real senders all pass."), status, steps);
  }

  /** TLS reports: loaded when opened, as they need their own look-up. */
  function tlsBox(d) {
    if (!d.address) return null;
    const body = el("div", {});
    const box = el("details", { class: "panel" }, el("summary", {}, el("h2", { style: { display: "inline" } }, "Encrypted delivery (TLS reports)")), body);
    let done = false;
    box.addEventListener("toggle", async () => {
      if (!box.open || done) return;
      done = true;
      body.replaceChildren(el("p", {}, el("span", { class: "spin" }), "Loading…"));
      const r = await api("GET", `/api/domains/${encodeURIComponent(d.domain)}/tls?days=${d.days}`);
      if (!r.ok) return body.replaceChildren(el("p", {}, r.body.error || "TLS reports couldn't be loaded."));
      const t = r.body, s = t.summary;
      body.replaceChildren(...[
        el("p", {}, "Mail servers that support TLS reporting (Google, Microsoft and others) send a daily report saying whether email to you arrived encrypted."),
        t.setup ? [el("p", {}, t.record ? "Add your report address to this record:" : "Add this record to get TLS reports:"), record(t.setup)] :
          el("p", { class: "ok-note" }, "✓ Your TLS reporting record sends reports here."),
        s.reports ? el("div", { class: "overview" }, ring(s.rate, "encrypted", s.rate >= 99 ? "passc" : s.rate >= 90 ? "warnc" : "failc"),
          el("div", {}, el("p", {}, `${plural(s.success + s.failure, "connection")} from ${s.reporters.map((x) => x.org).join(", ")}.`),
            s.problems.map((p) => el("div", { class: "check failc" }, el("div", { class: "check-head" }, el("span", { class: "icon" }, "✕"),
              el("div", {}, el("h4", {}, `${p.title} · ${plural(p.count, "time")}`), el("p", { class: "sum" }, p.fix, p.mx.length ? ` (${p.mx.join(", ")})` : "")))))))
          : el("p", { class: "small" }, "No TLS reports in this period yet."),
      ].flat().filter(Boolean));
    });
    return box;
  }

  function received(d) {
    if (!d.reports.length) return null;
    return el("section", { class: "panel" }, el("h2", {}, "Reports received"),
      el("div", { class: "scroll" }, el("table", { class: "tbl" },
        el("thead", {}, el("tr", {}, el("th", {}, "From"), el("th", {}, "Covers"), el("th", { class: "n" }, "Emails"), el("th", { class: "n" }, "Passed"))),
        el("tbody", {}, d.reports.map((x) => el("tr", {}, el("td", {}, x.org), el("td", {}, day(x.begin_at || x.created_at)),
          el("td", { class: "n" }, Number(x.messages).toLocaleString("en-GB")), el("td", { class: "n" }, `${pct(x.passed, x.messages)}%`)))))),
      el("p", { class: "small", style: { margin: "10px 0 0" } }, "What each report says is kept for 12 months, then deleted. The report files themselves aren't kept."));
  }

  /** Every row behind the findings, filtered, with a CSV download. */
  function everyRow(d) {
    const body = el("div", {});
    const box = el("details", { class: "panel" }, el("summary", {}, el("h2", { style: { display: "inline" } }, "Every row")), body);
    const filters = { result: "", sender: "", org: "", selector: "", disposition: "" };
    let offset = 0;
    async function load() {
      const q = new URLSearchParams({ days: String(d.days), offset: String(offset) });
      for (const [k, v] of Object.entries(filters)) if (v) q.set(k, v);
      body.replaceChildren(el("p", {}, el("span", { class: "spin" }), "Loading…"));
      const r = await api("GET", `/api/domains/${encodeURIComponent(d.domain)}/rows?${q}`);
      if (!r.ok) return body.replaceChildren(el("p", {}, r.body.error || "The rows couldn't be loaded."));
      const v = r.body;
      const pick = (key, text, options) => {
        const s = el("select", { onchange: () => { filters[key] = s.value; offset = 0; load(); } }, el("option", { value: "" }, `Any ${text}`),
          options.map((o) => el("option", { value: o[0], selected: filters[key] === o[0] }, o[1])));
        return el("label", { class: "small" }, text, s);
      };
      q.delete("offset");
      body.replaceChildren(
        el("div", { class: "filters" },
          pick("result", "result", [["pass", "Passed"], ["fail", "Failed"], ["forwarded", "Forwarded"]]),
          pick("sender", "sender", v.options.senders.map((o) => [o.key, o.name])),
          pick("org", "reporter", v.options.orgs.map((o) => [o.name, o.name])),
          pick("selector", "DKIM selector", v.options.selectors.map((o) => [o.name, o.name])),
          pick("disposition", "what was done", v.options.dispositions.map((o) => [o.name, o.name]))),
        el("p", { class: "small" }, `${plural(v.matched, "row")}, ${plural(v.messages, "email")}, ${pct(v.passed, v.messages)}% passed.`),
        el("div", { class: "scroll" }, el("table", { class: "tbl" },
          el("thead", {}, el("tr", {}, ["Date", "Reporter", "Server", "Sender", "Emails", "Result", "DKIM", "SPF", "Done"].map((h, i) => el("th", { class: i === 4 ? "n" : null }, h)))),
          el("tbody", {}, v.rows.map((x) => el("tr", {}, el("td", {}, day(x.end)), el("td", {}, x.org), el("td", {}, x.ip, x.ptr ? el("div", { class: "small" }, x.ptr) : null), el("td", {}, x.sender),
            el("td", { class: "n" }, Number(x.count).toLocaleString("en-GB")), el("td", {}, x.result), el("td", {}, x.dkim), el("td", {}, x.spf), el("td", {}, x.disposition)))))),
        el("div", { class: "acts" },
          offset > 0 ? btn("back", "Previous 100", { class: "btn quiet small", onclick: () => { offset = Math.max(0, offset - 100); load(); } }) : null,
          offset + 100 < v.matched ? btn("more", "Next 100", { class: "btn quiet small", onclick: () => { offset += 100; load(); } }) : null,
          el("a", { class: "btn quiet small", href: `/api/domains/${encodeURIComponent(d.domain)}/export?${q}`, html: icon("download") }, el("span", {}, "Download as CSV"))));
    }
    box.addEventListener("toggle", () => { if (box.open && !body.childNodes.length) load(); });
    return box;
  }

  function domainSettings(d) {
    const enc = encodeURIComponent(d.domain);
    const toggle = (text, hint, on, body) => {
      const box = el("input", { type: "checkbox", checked: on });
      box.addEventListener("change", async () => {
        const r = await api("POST", `/api/domains/${enc}/settings`, body(box.checked));
        if (!r.ok) box.checked = !box.checked;
      });
      return el("label", { class: "toggle" }, box, el("span", {}, text, hint ? el("small", {}, hint) : null));
    };
    const a = d.alerts;
    const shareOut = el("div", {});
    const share = btn("share", "Make a private link", { class: "btn quiet", onclick: async () => {
      const r = await api("POST", `/api/domains/${enc}/share`, { days: d.days });
      if (!r.ok) return say(shareOut, r.body.error);
      const url = `${location.origin}${r.body.path}`;
      shareOut.replaceChildren(el("p", { class: "small" }, `Anyone with this link can see these findings (not your settings) until ${day(r.body.expires)}:`), el("div", { class: "addr" }, el("code", {}, url), copyBtn(url)));
    } });
    const remove = btn("trash", "Remove this domain", { class: "btn danger" });
    remove.addEventListener("click", async () => {
      if (remove.dataset.sure !== "1") { remove.dataset.sure = "1"; label(remove, `Remove ${d.domain} and its reports? Press again`); return; }
      await api("DELETE", `/api/domains/${enc}`);
      go(""); route();
    });
    return el("section", { class: "panel" }, el("h2", {}, "Emails, sharing and settings"),
      el("p", { class: "small" }, "Emails go to the address in Settings."),
      toggle("New sender", "Someone new starts sending email as this domain", a.new, (on) => ({ alert: "new", on })),
      toggle("Your mail failing", "A sender that's yours starts failing DMARC", a.failing, (on) => ({ alert: "failing", on })),
      toggle("Only senders I've marked Mine", "For the alert above", a.mineOnly, (on) => ({ alert: "mineOnly", on })),
      toggle("Reports stopped", "No reports for 3 days, which usually means the DMARC record changed", a.silent, (on) => ({ alert: "silent", on })),
      toggle("Encryption failing", "From TLS reports", a.tls, (on) => ({ alert: "tls", on })),
      toggle("Next rollout step", "When it's safe to step up", d.reminders, (on) => ({ reminders: on })),
      toggle("Weekly summary", null, d.weekly, (on) => ({ weekly: on })),
      el("div", { class: "acts" }, share, btn("print", "Print or save as PDF", { class: "btn quiet", onclick: () => window.print() }), remove), shareOut);
  }

  // --- Uploads ---------------------------------------------------------------------------------------

  function uploadPage() {
    let chosen = [];
    const err = el("p", { class: "err", role: "alert", hidden: true });
    const picked = el("ul", { class: "picked" });
    const input = el("input", { type: "file", multiple: true, accept: ".xml,.gz,.zip,application/xml,application/gzip,application/zip", "aria-label": "Choose report files" });
    const drop = el("label", { class: "drop", html: icon("upload") }, el("b", {}, "Choose report files, or drop them here"), el("span", { class: "small" }, "XML, .gz or .zip, up to 10 files of 5 MB"), input);
    const goBtn = btn("upload", "Read my reports", { disabled: true });
    const pick = (files) => {
      chosen = [...files].slice(0, 10);
      say(err, files.length > 10 ? "Up to 10 files at a time: the first 10 are kept." : "");
      picked.replaceChildren(...chosen.map((f) => el("li", { class: f.size > 5 * 1048576 ? "bad" : "" }, el("span", {}, f.name), el("span", {}, f.size > 5 * 1048576 ? "Too big (over 5 MB)" : `${Math.ceil(f.size / 1024)} KB`))));
      goBtn.disabled = !chosen.length;
    };
    input.addEventListener("change", () => pick(input.files));
    for (const ev of ["dragenter", "dragover"]) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); });
    for (const ev of ["dragleave", "drop"]) drop.addEventListener(ev, () => drop.classList.remove("over"));
    drop.addEventListener("drop", (e) => { e.preventDefault(); if (e.dataTransfer && e.dataTransfer.files.length) pick(e.dataTransfer.files); });
    goBtn.addEventListener("click", async () => {
      const ok = chosen.filter((f) => f.size <= 5 * 1048576);
      if (!ok.length) return say(err, "Please choose report files of 5 MB or less.");
      const data = new FormData();
      for (const f of ok) data.append("file", f, f.name);
      loading(`Reading ${plural(ok.length, "report file")}…`);
      const r = await api("POST", "/api/upload", data);
      if (!r.ok) { uploadPage(); return; }
      go(`upload=${r.body.id}`);
      showResults(r.body);
    });
    show(el("section", { class: "panel" }, el("h1", {}, "Upload report files"),
      el("p", { class: "lead" }, "Got DMARC reports as attachments already? Upload them to see what they say. They're kept under Your uploads until you delete them."),
      drop, picked, el("div", { class: "acts" }, goBtn), err));
  }

  function showResults(body) {
    const parts = [backBtn("Your domains", () => { go(""); route(); })];
    if (body.files) parts.push(el("section", { class: "panel" }, el("h2", {}, "Your files"),
      el("ul", { class: "files" }, body.files.map((f) => el("li", { class: f.ok ? "" : "bad" }, f.ok ? `✓ ${f.name}: a report from ${f.org} about ${f.domain}` : `✕ ${f.name}: ${f.error}`)))));
    for (const a of body.results) parts.push(overview({ analysis: a }), senders(a, a.domain, true));
    parts.push(el("section", { class: "panel" }, el("h2", {}, "Want these every day without uploading?"),
      el("p", {}, "Add the domain under Your domains and point its DMARC record at your report address. Reports then arrive by themselves."),
      el("div", { class: "acts" },
        body.results[0] ? btn("plus", `Add ${body.results[0].domain}`, { onclick: async () => {
          const x = await api("POST", "/api/domains", { domain: body.results[0].domain });
          if (x.ok) { go(`domain=${encodeURIComponent(x.body.domain)}`); route(); }
        } }) : null,
        btn("trash", "Delete this upload", { class: "btn danger", onclick: async () => { await api("DELETE", `/api/uploads/${body.id}`); go(""); route(); } }))));
    show(...parts.filter(Boolean));
  }

  async function showUpload(id) {
    loading("Loading your upload…");
    const r = await api("GET", `/api/uploads/${encodeURIComponent(id)}`);
    if (!r.ok) return fail(r.body.error || "That upload couldn't be loaded.");
    showResults(r.body);
  }

  // --- Settings --------------------------------------------------------------------------------------

  async function settingsPage() {
    loading("Loading your settings…");
    const r = await api("GET", "/api/settings");
    if (!r.ok) return fail(r.body.error || "Your settings couldn't be loaded.");
    const s = r.body;

    // Where reports and alerts go.
    const rep = el("input", { type: "email", value: s.reportAddress || "", placeholder: "dmarc-reports@example.com" });
    const alertTo = el("input", { type: "email", value: s.alertTo || "", placeholder: "you@example.com" });
    const msg1 = el("p", { class: "ok-note", role: "status", hidden: true });
    const err1 = el("p", { class: "err", role: "alert", hidden: true });
    const save1 = btn("save", "Save", { type: "submit" });
    const test = btn("mail", "Send a test email", { class: "btn quiet" });
    test.addEventListener("click", async () => {
      say(msg1, ""); say(err1, "");
      test.disabled = true;
      const x = await api("POST", "/api/test-email");
      test.disabled = false;
      if (x.ok) say(msg1, `Sent to ${alertTo.value}.`); else say(err1, x.body.error);
    });
    const where = el("form", { class: "panel" }, el("h1", {}, "Settings"), el("h2", {}, "Where reports and alerts go"),
      el("label", { class: "field" }, "Report address", el("small", {}, "Mail providers send reports here. In Cloudflare, open Email › Email Routing for its domain and route this address to the dmarc-reports Worker."), rep),
      el("label", { class: "field" }, "Send alerts to", el("small", {}, s.canEmail ? "Must be verified under Email Routing › Destination addresses in Cloudflare." : "Sending email isn't switched on for this install (it needs the EMAIL binding)."), alertTo),
      s.lastReportAt ? el("p", { class: "small" }, `Last report arrived ${day(s.lastReportAt)}.`) : el("p", { class: "small" }, "No reports have arrived by email yet."),
      el("div", { class: "acts" }, save1, s.canEmail ? test : null), msg1, err1);
    where.addEventListener("submit", async (e) => {
      e.preventDefault();
      say(msg1, ""); say(err1, "");
      const x = await api("POST", "/api/settings", { reportAddress: rep.value.trim(), alertTo: alertTo.value.trim() });
      if (x.ok) say(msg1, "Saved."); else say(err1, x.body.error);
    });

    // Branding (white label).
    const name = el("input", { type: "text", value: brand.name, maxlength: "40" });
    const colour = el("input", { type: "color", value: brand.colour });
    const support = el("input", { type: "email", value: brand.support || "", placeholder: "help@example.com" });
    let logo = brand.logo;
    const preview = el("img", { class: "logo-preview", alt: "", src: logo || "/favicon.svg" });
    const file = el("input", { type: "file", accept: "image/png,image/jpeg,image/webp,image/svg+xml", hidden: true });
    file.addEventListener("change", () => {
      const f = file.files[0];
      if (!f) return;
      if (f.size > 150 * 1024) return say(err2, "That picture is too big. Please use one under 150 KB.");
      const rd = new FileReader();
      rd.onload = () => { logo = rd.result; preview.src = logo; };
      rd.readAsDataURL(f);
    });
    const msg2 = el("p", { class: "ok-note", role: "status", hidden: true });
    const err2 = el("p", { class: "err", role: "alert", hidden: true });
    const brandForm = el("form", { class: "panel" }, el("h2", {}, "Branding"),
      el("p", {}, "Put your own name, logo and colour on the app, its emails and shared links."),
      el("p", { class: "small" }, "Using it for your own domains is free up to 10. Running it for clients or under your own brand for others needs a commercial licence: ",
        el("a", { href: "https://paulobrien.dev/contact/", target: "_blank", rel: "noopener" }, "get in touch"), "."),
      el("label", { class: "field" }, "Name", name),
      el("div", { class: "brand-row" }, preview, btn("image", "Choose a logo", { class: "btn quiet small", onclick: () => file.click() }),
        btn("undo", "Standard logo", { class: "btn quiet small", onclick: () => { logo = null; preview.src = "/favicon.svg"; } }), file),
      el("label", { class: "field", style: { "margin-top": "14px" } }, "Colour", colour),
      el("label", { class: "field" }, "Support email", el("small", {}, "Optional. Shown at the bottom of every page."), support),
      el("div", { class: "acts" }, btn("save", "Save branding", { type: "submit" }),
        btn("undo", "Back to the standard look", { class: "btn quiet", onclick: async () => { const x = await api("POST", "/api/brand", { name: null, colour: null, logo: null, support: null }); if (x.ok) { applyBrand(x.body); settingsPage(); } } })),
      msg2, err2);
    brandForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      say(msg2, ""); say(err2, "");
      const x = await api("POST", "/api/brand", { name: name.value, colour: colour.value, logo, support: support.value.trim() });
      if (!x.ok) return say(err2, x.body.error);
      applyBrand(x.body);
      say(msg2, "Saved.");
    });

    // Password.
    const cur = el("input", { type: "password", autocomplete: "current-password" });
    const pw = el("input", { type: "password", autocomplete: "new-password", minlength: "10" });
    const msg3 = el("p", { class: "ok-note", role: "status", hidden: true });
    const err3 = el("p", { class: "err", role: "alert", hidden: true });
    const pwForm = el("form", { class: "panel" }, el("h2", {}, "Password"),
      el("label", { class: "field" }, "Current password", cur), el("label", { class: "field" }, "New password", el("small", {}, "At least 10 characters. Everywhere else you're signed in is signed out."), pw),
      el("div", { class: "acts" }, btn("key", "Change password", { type: "submit" })), msg3, err3);
    pwForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      say(msg3, ""); say(err3, "");
      const x = await api("POST", "/api/password", { current: cur.value, password: pw.value });
      if (!x.ok) return say(err3, x.body.error);
      cur.value = pw.value = "";
      say(msg3, "Your password is changed.");
    });

    show(where, brandForm, pwForm, el("section", { class: "panel" }, el("h2", {}, "About"),
      el("p", {}, `Version ${s.version}. `, el("a", { href: "https://github.com/pobren/dmarc-reports/releases", target: "_blank", rel: "noopener" }, "What's new"), " · ",
        el("a", { href: "https://github.com/pobren/dmarc-reports/blob/main/LICENSE", target: "_blank", rel: "noopener" }, "Licence"))));
  }

  // --- A shared link ---------------------------------------------------------------------------------

  async function shared(id) {
    nav.hidden = true;
    loading("Opening the shared report…");
    const r = await api("GET", `/api/share/${encodeURIComponent(id)}`);
    if (!r.ok) return fail(r.body.error || "That shared report couldn't be opened.");
    const b = r.body;
    show(el("div", { class: "note" }, `Shared DMARC findings for ${b.domain}, covering the last ${b.days === 365 ? "12 months" : `${b.days} days`}. This link works until ${day(b.expires)}.`),
      overview({ analysis: b.analysis }), senders(b.analysis, b.domain, true));
  }

  start();
})();
