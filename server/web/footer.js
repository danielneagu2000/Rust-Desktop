// Footer comun, construit din site.json ("footer"): meniu, sedii, insigne ANPC, Facebook,
// ceasul (ora României), drepturi de autor. Linkurile se schimbă în site.json, nu aici.
(function () {
  "use strict";
  var el = document.getElementById("site-footer");
  if (!el) return;

  function esc(v) {
    return String(v == null ? "" : v).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function href(u) {
    u = String(u || "");
    return /^(https?:|mailto:|tel:|\/|[a-z0-9_-]+\.html)/i.test(u) ? esc(u) : "#";
  }
  function link(it) {
    var ext = /^https?:/i.test(it.url || "") && !/^https?:\/\/remote\./i.test(it.url);
    return '<a href="' + href(it.url) + '"' + (ext ? ' rel="noopener"' : "") + ">" + esc(it.text) + "</a>";
  }
  var PIN = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2a7 7 0 0 0-7 7c0 5.2 7 13 7 13s7-7.8 7-13a7 7 0 0 0-7-7zm0 9.5A2.5 2.5 0 1 1 12 6.5a2.5 2.5 0 0 1 0 5z"/></svg>';
  var PHONE = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M6.6 10.8a15.1 15.1 0 0 0 6.6 6.6l2.2-2.2a1 1 0 0 1 1-.25 11.4 11.4 0 0 0 3.6.57 1 1 0 0 1 1 1V20a1 1 0 0 1-1 1A17 17 0 0 1 3 4a1 1 0 0 1 1-1h3.5a1 1 0 0 1 1 1c0 1.25.2 2.45.57 3.6a1 1 0 0 1-.25 1z"/></svg>';
  var MAIL = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M3 5h18a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1zm9 7.2L4 7.3V17h16V7.3z"/></svg>';
  var FB = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2a10 10 0 0 0-1.6 19.9v-7H7.9V12h2.5V9.8c0-2.5 1.5-3.9 3.8-3.9 1.1 0 2.2.2 2.2.2v2.5h-1.3c-1.2 0-1.6.8-1.6 1.6V12h2.8l-.4 2.9h-2.3v7A10 10 0 0 0 12 2z"/></svg>';
  var RO = '<svg viewBox="0 0 3 2"><rect width="1" height="2" fill="#002b7f"/><rect x="1" width="1" height="2" fill="#fcd116"/><rect x="2" width="1" height="2" fill="#ce1126"/></svg>';
  var EU = '<svg viewBox="0 0 30 20"><rect width="30" height="20" fill="#003399"/><g fill="#ffcc00">' +
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11].map(function (i) {
      var a = i * Math.PI / 6;
      return '<circle cx="' + (15 + 6 * Math.sin(a)).toFixed(2) + '" cy="' + (10 - 6 * Math.cos(a)).toFixed(2) + '" r="0.9"/>';
    }).join("") + "</g></svg>";

  function item(icon, label, value) {
    return '<div class="ft-item">' + icon + '<div><div class="ft-label">' + esc(label) + '</div><div class="ft-value">' + value + "</div></div></div>";
  }

  function render(s) {
    var f = s.footer || {}, company = s.company || "RDN Network Data";
    var contacts = (f.offices || []).map(function (o) { return item(PIN, o.label, esc(o.address)); });
    if (s.phone) contacts.push(item(PHONE, "Mobil", '<a href="tel:' + esc(String(s.phone).replace(/[^+\d]/g, "")) + '">' + esc(s.phone) + "</a>"));
    if (s.email) contacts.push(item(MAIL, "Email", '<a href="mailto:' + esc(s.email) + '">' + esc(s.email) + "</a>"));

    var badges = [];
    if (f.anpc_sal_url) badges.push('<a class="ft-badge" href="' + href(f.anpc_sal_url) + '" rel="noopener"><span class="flag">' + RO +
      'ANPC</span><span class="txt">SAL - Soluționarea alternativă a litigiilor - ANPC</span></a>');
    if (f.sol_url) badges.push('<a class="ft-badge" href="' + href(f.sol_url) + '" rel="noopener"><span class="flag">' + EU +
      'UE</span><span class="txt">SOL - Soluționarea online a litigiilor</span></a>');
    if (f.facebook_url) badges.push('<a class="ft-fb" href="' + href(f.facebook_url) + '" rel="noopener">' + FB + "Facebook</a>");

    var legal = (f.legal || []).map(link);
    legal.push('<a href="confidentialitate.html">Confidențialitate RDN Remote</a>');
    legal.push('<span>Bazat pe <a href="https://github.com/rustdesk/rustdesk" rel="noopener">RustDesk</a> (AGPL-3.0)</span>');
    legal.push('<a href="' + href(s.source_url || "https://github.com/danielneagu2000/Rust-Desktop") + '" rel="noopener">Cod sursă</a>');

    el.innerHTML =
      '<div class="ft-top"><div class="ft-wrap">' +
        ((f.menu || []).length ? '<nav class="ft-menu" aria-label="Meniu RDN Network Data">' + f.menu.map(link).join("") + "</nav>" : "") +
        '<div class="ft-info"><div class="ft-contacts">' + contacts.join("") + '</div><div class="ft-badges">' + badges.join("") + "</div></div>" +
      "</div></div>" +
      '<div class="ft-bottom">' +
        '<div class="ft-clock">Data și ora: <span id="ft-now"></span> (RO)</div>' +
        '<div class="ft-wrap"><div class="ft-legal"><div class="row">' +
          "<span>Copyright " + esc(f.since || "2018") + " - " + new Date().getFullYear() + " " + esc(company) + "</span>" +
          '<span class="sep">|</span><span>All Rights Reserved</span><span class="sep">|</span>' +
          "<span>Powered by <b>" + esc(company) + "</b></span>" +
          (legal.length ? '<span class="sep"></span>' + legal.join('<span class="sep">·</span>') : "") +
        '</div><a class="ft-logo" href="' + href(f.home_url || "/") + '" aria-label="' + esc(company) + '"><img src="assets/logo.png" alt=""></a></div>' +
      "</div></div>";

    var now = document.getElementById("ft-now");
    var fmt = new Intl.DateTimeFormat("ro-RO", { timeZone: "Europe/Bucharest", day: "2-digit", month: "2-digit", year: "numeric",
      hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
    function tick() { now.textContent = fmt.format(new Date()); }
    tick();
    setInterval(tick, 1000);
  }

  fetch("site.json", { cache: "no-store" })
    .then(function (r) { return r.ok ? r.json() : {}; })
    .catch(function () { return {}; })
    .then(render);
})();
