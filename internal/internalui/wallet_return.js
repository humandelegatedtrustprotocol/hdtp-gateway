// The web wallet's answer arrives in this page's fragment: #chain=<leaf>.<root>&state=<state>, or
// #error=<code>&state=<state> (PACT §9.1). A fragment never reaches a server or a Referer. The
// script takes it out of the address bar at once, then POSTs it to this node same-site, where the
// session and CSRF cookies (SameSite=Strict, so absent on the wallet's cross-site navigation here)
// are sent, and the install goes through the portal's one authorisation.
(function () {
  var out = document.getElementById("out");
  function say(text, cls) { out.textContent = text; out.className = cls || ""; }
  var answer = new URLSearchParams(location.hash.slice(1));
  var slug = new URLSearchParams(location.search).get("slug") || "";
  history.replaceState(null, "", location.pathname + location.search);
  // A wallet's refusal is a code (PACT §9.1 names `cancelled`), shown as a fixed sentence and never
  // as the text the fragment carries: anyone can link here with any fragment, and the page must not
  // say what a link tells it to.
  var refusals = { cancelled: "You declined in your wallet. Nothing was installed." };
  if (answer.get("error")) {
    say(refusals[answer.get("error")] || "Your wallet did not sign. Nothing was installed.", "err");
    return;
  }
  var chain = answer.get("chain"), state = answer.get("state");
  if (!chain || !state || !slug) {
    say("Nothing to install: this is where your wallet sends its answer.", "err");
    return;
  }
  var name = document.querySelector('meta[name="pact-csrf-cookie"]').content + "=";
  var csrf = "";
  document.cookie.split("; ").forEach(function (c) { if (c.indexOf(name) === 0) csrf = c.slice(name.length); });
  fetch("/identity/" + encodeURIComponent(slug) + "/wallet/install", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Pact-Csrf": csrf },
    body: new URLSearchParams({ chain: chain, state: state }).toString(),
  }).then(function (r) {
    if (r.status === 401) {
      say("Not installed: sign in to this node's portal in this browser, then send the answer again from your wallet.", "err");
      return;
    }
    return r.json().then(function (j) {
      if (r.ok) {
        var warned = (j.warnings || []).length > 0;
        say("Installed: " + j.endpoint + ", valid until " + j.not_after + "." + (j.notice ? " " + j.notice : "") +
          (warned ? " Warning: " + j.warnings.join(" ") : ""), warned ? "warn" : "ok");
      } else {
        say("Not installed: " + (j.error || "refused") + ".", "err");
      }
    });
  }).catch(function () {
    say("This node could not be reached to install the certificate.", "err");
  });
})();
