// The web wallet's answer arrives in this page's fragment: #chain=<leaf>.<root>&state=<state>, or
// #error=<code>&state=<state> (HDTP §9.1). A fragment never reaches a server or a Referer. The
// script takes it out of the address bar at once, then POSTs it to this node same-site, where the
// session and CSRF cookies (SameSite=Strict, so absent on the wallet's cross-site navigation here)
// are sent, and the install goes through the portal's one authorisation.
//
// The page carries every state's words (wallet_pages.go, walletReturnStates); this script only
// chooses one, fills in what the install answered, and shows the actions that help. It writes text,
// never markup.
(function () {
  function el(id) { return document.getElementById(id); }
  var card = el("answer");
  var answer = new URLSearchParams(location.hash.slice(1));
  var slug = new URLSearchParams(location.search).get("slug") || "";
  history.replaceState(null, "", location.pathname + location.search);
  var signPath = "/identity/" + encodeURIComponent(slug) + "/wallet";

  // show replaces the working state with `id`'s: kind is the card's colour ("ok", "warn", "err" or
  // "" for neutral), actions the links it offers besides Back to Identity ("sign", "login"), detail
  // the quiet line under it.
  function show(id, kind, actions, detail) {
    el("st-working").hidden = true;
    el("st-" + id).hidden = false;
    card.setAttribute("data-kind", kind);
    var d = el("detail");
    d.textContent = detail || "";
    d.hidden = !detail;
    var sign = el("a-sign"), login = el("a-login");
    sign.hidden = !(slug && actions.indexOf("sign") >= 0);
    if (!sign.hidden) sign.href = signPath;
    login.hidden = !(slug && actions.indexOf("login") >= 0);
    if (!login.hidden) login.href = "/login?next=" + encodeURIComponent(signPath);
    el("actions").hidden = false;
    card.setAttribute("aria-busy", "false");
  }

  // A wallet's refusal is a code (HDTP §9.1 names `cancelled`; BatonDeck's wallet also sends
  // `failed`), shown by a fixed state and never as the text the fragment carries: anyone can link
  // here with any fragment, and the page must not say what a link tells it to. A code the page does
  // not know is not even repeated in the detail line.
  var walletCodes = { cancelled: "wallet_cancelled", failed: "wallet_failed" };
  var werr = answer.get("error");
  if (werr) {
    var known = Object.prototype.hasOwnProperty.call(walletCodes, werr);
    show(known ? walletCodes[werr] : "wallet_other", werr === "cancelled" ? "" : "err", ["sign"], "");
    return;
  }
  var chain = answer.get("chain"), state = answer.get("state");
  if (!chain || !state || !slug) {
    show("empty", "", [], "");
    return;
  }

  // The instant as the answer gives it, in UTC: "30 Sep 2027, 14:05 UTC".
  var months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  function when(iso) {
    var t = new Date(iso);
    if (!iso || isNaN(t.getTime())) return iso || "";
    function two(n) { return (n < 10 ? "0" : "") + n; }
    return t.getUTCDate() + " " + months[t.getUTCMonth()] + " " + t.getUTCFullYear() + ", " +
      two(t.getUTCHours()) + ":" + two(t.getUTCMinutes()) + " UTC";
  }

  function installed(j) {
    var warnings = j.warnings || [];
    var warned = warnings.length > 0;
    el("f-name").textContent = j.name || slug;
    el("f-address").textContent = j.endpoint || "";
    el("f-from").textContent = when(j.not_before);
    el("f-until").textContent = when(j.not_after);
    el("f-notice").textContent = j.notice || "";
    el("f-notice").hidden = !j.notice;
    // A warning is the node's sentence, which begins in lower case (cli/leafservice.go).
    el("f-warnings").textContent = warnings.map(function (w) { return w.charAt(0).toUpperCase() + w.slice(1); }).join(" ");
    el("f-warn").hidden = !warned;
    el("p-installed").hidden = warned;
    el("p-installed-warn").hidden = !warned;
    el("i-installed").hidden = warned;
    el("i-installed-warn").hidden = !warned;
    show("installed", warned ? "warn" : "ok", [], "");
  }

  // The install's refusals, by the code it answers (wallet_pages.go, walletRefusals): each is the
  // state r-<code>, so a code names a refusal state and nothing else. Any other answer is a plain
  // refusal with what the node said.
  var noSign = { answered: true, not_found: true };
  function refused(status, j) {
    var code = j && typeof j.code === "string" && /^[a-z_]+$/.test(j.code) ? j.code : "";
    var msg = j && typeof j.error === "string" ? j.error : "";
    if (code && el("st-r-" + code)) {
      // A state the page explains in words shows no code (the owner, 2026-09-30: "what is no_request
      // here?"). The chain and malformed refusals add the node's own sentence, which names the rule;
      // a failure nobody expected keeps a labelled reference, which is what helps someone diagnose.
      var detail = (code === "chain" || code === "malformed") && msg ? msg : code === "failed" ? "Reference: HTTP " + status : "";
      show("r-" + code, code === "answered" ? "ok" : "err", noSign[code] ? [] : ["sign"], detail);
      return;
    }
    show("refused", "err", ["sign"], "Reference: HTTP " + status + (msg ? " — " + msg : ""));
  }

  fetch("/identity/" + encodeURIComponent(slug) + "/wallet/install", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "X-HDTP-Csrf": readCsrf() },
    body: new URLSearchParams({ chain: chain, state: state }).toString(),
  }).then(function (r) {
    // The portal refuses before the install, as text: no session (401), the CSRF check (403).
    if (r.status === 401) return show("signed_out", "err", ["login"], "");
    if (r.status === 403) return show("forbidden", "err", ["sign"], "");
    return r.json().then(function (j) {
      if (r.ok) installed(j);
      else refused(r.status, j);
    }, function () {
      refused(r.status, null);
    });
  }).catch(function () {
    show("unreachable", "warn", [], "");
  });

  function readCsrf() {
    var name = document.querySelector('meta[name="hdtp-csrf-cookie"]').content + "=";
    var csrf = "";
    document.cookie.split("; ").forEach(function (c) { if (c.indexOf(name) === 0) csrf = c.slice(name.length); });
    return csrf;
  }
})();
