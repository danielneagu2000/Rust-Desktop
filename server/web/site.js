/* Pagina RDN Remote: meniul de pe telefon, antetul la derulare, butonul „înapoi sus”, adresele secțiunilor
   (/descarcare/, /preturi/ ...), exemplul de sesiune din primul ecran și apariția cardurilor la derulare. */
(function () {
  "use strict";
  var still = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* Exemplul de sesiune din primul ecran */
  (function () {
    var code = document.getElementById("demo-code");
    if (!code) return;
    var states = [
      { label: "se conectează", code: "ID 482 913 607 · RECEPTIE-PC", text: "Introduci ID-ul și parola unică primite de la persoana pe care o ajuți.", link: "se caută" },
      { label: "autentificat", code: "parola unică acceptată · 2FA", text: "Cheile de criptare se stabilesc direct între cele două dispozitive.", link: "directă" },
      { label: "în sesiune", code: "ecran · fișiere · chat · terminal", text: "Serverul doar pune dispozitivele în legătură. Nu vede imaginea, tastatura sau fișierele.", link: "directă" }
    ];
    var label = document.getElementById("demo-state"), link = document.getElementById("demo-link"),
        explain = document.getElementById("demo-explain"), i = 0;
    function show(k) {
      var s = states[k];
      code.textContent = s.code;
      label.textContent = s.label;
      link.textContent = s.link;
      explain.textContent = s.text;
    }
    show(still ? 2 : 0);
    if (still) return;
    setInterval(function () {
      code.classList.add("fade");
      setTimeout(function () { i = (i + 1) % states.length; show(i); code.classList.remove("fade"); }, 350);
    }, 3200);
  })();

  /* Butonul „înapoi sus” apare după ce ai derulat puțin; antetul primește umbră */
  (function () {
    var top = document.getElementById("toTop"), head = document.querySelector(".top");
    function toggle() {
      var y = window.scrollY;
      if (top) top.classList.toggle("off", y < 500);
      if (head) head.classList.toggle("scrolled", y > 8);
    }
    toggle();
    window.addEventListener("scroll", toggle, { passive: true });
    if (top) top.addEventListener("click", function (e) {
      e.preventDefault();
      window.scrollTo({ top: 0, behavior: still ? "auto" : "smooth" });
    });
  })();

  /* Meniul de pe telefon */
  (function () {
    var btn = document.getElementById("menuBtn"), nav = document.getElementById("nav");
    if (!btn || !nav) return;
    function set(open) {
      nav.classList.toggle("open", open);
      btn.setAttribute("aria-expanded", open ? "true" : "false");
      btn.setAttribute("aria-label", open ? "Închide meniul" : "Deschide meniul");
    }
    btn.addEventListener("click", function () { set(!nav.classList.contains("open")); });
    nav.addEventListener("click", function (e) { if (e.target.closest("a")) set(false); });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") set(false); });
  })();

  /* Adresele secțiunilor: serverul răspunde la ele cu aceeași pagină (Caddyfile); aici derulăm la secțiune
     și schimbăm adresa din bară. Linkurile vechi cu „#sectiune” duc la adresa nouă. */
  (function () {
    var IDS = ["functii", "preturi", "descarcari", "cum", "siguranta", "intrebari", "contact"];
    var EN = /^\/en(\/|$)/.test(location.pathname), BASE = EN ? "/en/" : "/";
    var SLUGS = EN ? ["features", "pricing", "download", "how-it-works", "security", "faq", "contact"]
                   : ["functii", "preturi", "descarcare", "cum-functioneaza", "siguranta", "intrebari", "contact"];
    var TITLES = EN ? ["Features", "Pricing", "Download", "How it works", "Security", "FAQ", "Contact"]
                    : ["Funcții", "Prețuri", "Descărcare", "Cum funcționează", "Siguranță", "Întrebări frecvente", "Contact"];
    var baseTitle = document.title;
    function idFromPath(path) {
      if (EN !== /^\/en\//.test(path)) return "";
      var k = SLUGS.indexOf(path.slice(BASE.length - 1).replace(/^\/+|\/+$/g, ""));
      return k < 0 ? "" : IDS[k];
    }
    function pathFor(id) {
      var k = IDS.indexOf(id);
      return k < 0 ? null : BASE + SLUGS[k] + "/";
    }
    function go(id, smooth) {
      var el = id && document.getElementById(id);
      if (el) el.scrollIntoView({ block: "start", behavior: smooth && !still ? "smooth" : "auto" });
      else window.scrollTo({ top: 0, behavior: smooth && !still ? "smooth" : "auto" });
      var k = IDS.indexOf(id);
      document.title = k < 0 ? baseTitle : TITLES[k] + " · RDN Remote";
    }
    var start = idFromPath(location.pathname);
    if (!start && location.hash && pathFor(location.hash.slice(1))) {
      start = location.hash.slice(1);
      history.replaceState(null, "", pathFor(start));
    } else if (start && location.pathname !== pathFor(start)) {
      history.replaceState(null, "", pathFor(start));
    }
    if (start) {
      go(start, false);
      window.addEventListener("load", function () { if (idFromPath(location.pathname) === start) go(start, false); });
    }
    document.addEventListener("click", function (e) {
      var a = e.target.closest("a[href]");
      if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      if (a.target || a.origin !== location.origin || a.hasAttribute("download")) return;
      var id = idFromPath(a.pathname), home = a.pathname === BASE && !a.hash;
      if (!id && !home) return;
      e.preventDefault();
      if (a.pathname !== location.pathname) history.pushState(null, "", a.pathname);
      go(id, true);
    });
    if ("scrollRestoration" in history) history.scrollRestoration = "manual";
    window.addEventListener("popstate", function () { go(idFromPath(location.pathname), false); });
  })();

  /* Cardurile apar ușor la derulare. Fără JavaScript sau cu „mișcare redusă”, totul e vizibil de la început. */
  (function () {
    if (still || !("IntersectionObserver" in window)) return;
    var items = document.querySelectorAll(".mod, .plan, .trap, .qa, .route li, .code-info, .price-wrap, .contact");
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (!en.isIntersecting) return;
        var t = en.target;
        io.unobserve(t);
        t.classList.add("in");
        t.addEventListener("transitionend", function done() { t.classList.remove("reveal", "in"); t.removeEventListener("transitionend", done); });
      });
    }, { rootMargin: "0px 0px -8% 0px" });
    items.forEach(function (el) {
      if (el.getBoundingClientRect().top < window.innerHeight) return;
      el.classList.add("reveal");
      io.observe(el);
    });
  })();
})();
