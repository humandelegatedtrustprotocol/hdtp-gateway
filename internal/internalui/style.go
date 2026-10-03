package internalui

// The brand for the few pages the node renders server-side: the web wallet's three pages, the OAuth
// "you can close this tab" page and the public invite landing. The portal itself is the embedded SPA
// (web/), which carries the brand in web/src/brand.css; these pages carry the same palette, type and
// motion inline, and TestServerPagesCarryTheBrandPalette holds every token here to that file's value,
// light and dark, so the two cannot drift apart.
//
// Two variants, by where the page is served. portalStyle is for the portal's own origin, where the
// self-hosted fonts and the brand files are one path away (the portal's CSP allows 'self'). landingStyle
// is for the invite landing on the PUBLIC listener, which serves neither and promises "no external
// assets": its mark is inline (landingMark) and its type falls back to the system's faces.

// brandPalette is web/src/brand.css's palette, the tokens these pages use.
const brandPalette = `:root{--bg:#FFFFFF;--bg-2:#FAF8F4;--ink:#15181E;--text:#2B2F36;--muted:#5E6168;--line:#ECE8E0;--line-2:#DDD8CE;` +
	`--accent:#F38020;--accent-soft:#FDF0E4;--accent-ink:#AB5309;--accent-ui:#D9690C;--amber:#7A5A00;--red:#B3261E;` +
	`--sans:'Inter',system-ui,sans-serif;--mono:'JetBrains Mono',ui-monospace,monospace;` +
	`--display:'Bricolage Grotesque',var(--sans);--ease-out:cubic-bezier(.2,.75,.2,1)}
@media (prefers-color-scheme:dark){:root{--bg:#15181E;--bg-2:#1D2027;--ink:#F4F1EA;--text:#D6D2CA;--muted:#B3AEA5;--line:#2A2E36;--line-2:#373C46;` +
	`--accent:#F38020;--accent-soft:#33261A;--accent-ink:#FFA552;--accent-ui:#F38020;--amber:#E9B949;--red:#FF9C8A}}
`

// pageBase lays a server page out on the palette: one column, the display face on headings, the kit's
// `rise` for the blocks as the page arrives (a block that is or holds a form is never hidden: it moves
// at full opacity), and no motion under reduced motion.
const pageBase = `*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.6 var(--sans);-webkit-font-smoothing:antialiased}
main{max-width:640px;margin:0 auto;padding:40px 24px}
h1,h2{color:var(--ink);font-family:var(--display);font-optical-sizing:auto;letter-spacing:-.02em;line-height:1.2;margin:0 0 .5em}
h1{font-size:1.75rem;font-weight:700;letter-spacing:-.03em} h2{font-size:1.15rem}
a{color:var(--accent-ink)}
code,pre{font-family:var(--mono)}
code{overflow-wrap:anywhere}
strong{color:var(--ink)}
.muted{color:var(--muted);font-size:14px}
.brand{display:flex;align-items:center;gap:.55rem;margin:0 0 28px;color:var(--ink);font-weight:700;letter-spacing:-.02em}
.brand img{display:block;height:28px;width:auto}
.brand svg{display:block;width:30px;height:30px}
button{font:inherit;font-size:.9rem;font-weight:600;height:36px;padding:0 .95rem;display:inline-flex;align-items:center;justify-content:center;white-space:nowrap;max-width:100%;border-radius:9px;border:1px solid var(--ink);background:var(--ink);color:var(--bg);cursor:pointer}
:focus-visible{outline:2px solid var(--accent-ui);outline-offset:2px}
@keyframes rise{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}
@keyframes lift{from{transform:translateY(10px)}to{transform:none}}
main>*{animation:rise .38s var(--ease-out) both}
main>:nth-child(2){animation-delay:45ms} main>:nth-child(3){animation-delay:90ms} main>:nth-child(n+4){animation-delay:135ms}
main>:is(form,:has(form,input,button)){animation-name:lift}
@media (prefers-reduced-motion:reduce){main>*{animation:none}}
`

// fontFaces are the portal's self-hosted faces (web/public/fonts, hdtp-web-kit's).
const fontFaces = `@font-face{font-family:'Inter';src:url(/fonts/inter-latin-wght.woff2) format('woff2');font-weight:100 900;font-display:swap}
@font-face{font-family:'JetBrains Mono';src:url(/fonts/jbmono-latin-400.woff2) format('woff2');font-weight:400;font-display:swap}
@font-face{font-family:'Bricolage Grotesque';src:url(/fonts/bricolage-grotesque-latin-wght.woff2) format('woff2');font-weight:200 800;font-display:swap}
`

// portalStyle is the stylesheet of a server page on the portal's origin.
const portalStyle = `<style>
` + fontFaces + brandPalette + pageBase + `</style>`

// portalBrand is the product's wordmark at the top of a server page on the portal's origin: the kit's
// files (web/public/brand), the dark variant on a dark ground, exactly as the SPA shows it (ui.tsx).
const portalBrand = `<a class="brand" href="/"><picture><source srcset="/brand/hdtp-gateway-inline-dark.svg" media="(prefers-color-scheme: dark)"/>` +
	`<img src="/brand/hdtp-gateway-inline.svg" alt="HDTP Gateway" width="151" height="28"/></picture></a>`

// landingStyle is the invite landing's: the same palette and layout, no font files.
const landingStyle = `<style>
` + brandPalette + pageBase + `.card{border:1px solid var(--line);border-radius:14px;padding:24px;margin:16px 0;background:var(--bg-2)}
pre{white-space:pre-wrap;word-break:break-all;font-size:13px;line-height:1.5}
img{max-width:200px;height:auto}
</style>`

// landingMark is hdtp-web-kit's mark (kit/brand/mark.svg), inline because the public listener serves no
// files. No xmlns: the HTML parser places an inline <svg> in the SVG namespace by itself.
const landingMark = `<svg viewBox="0 0 120 120" aria-hidden="true"><defs><mask id="hdtp-landing-m" maskUnits="userSpaceOnUse" x="0" y="0" width="120" height="120">` +
	`<rect width="120" height="120" fill="white"/><path d="M34 33 Q60 80 86 33" fill="none" stroke="black" stroke-width="7" stroke-linecap="round"/>` +
	`<path d="M34 33 C34 56 27 70 14 78 M86 33 C86 56 93 70 106 78" fill="none" stroke="black" stroke-width="6.5" stroke-linecap="round"/>` +
	`<path d="M34 27 V90 M86 27 V90" stroke="black" stroke-width="9" stroke-linecap="round"/><path d="M14 78 H106" stroke="black" stroke-width="7" stroke-linecap="round"/></mask></defs>` +
	`<rect x="8" y="8" width="104" height="104" rx="26" fill="#F38020" mask="url(#hdtp-landing-m)"/></svg>`
