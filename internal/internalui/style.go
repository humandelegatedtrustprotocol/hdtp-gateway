package internalui

// portalStyle is the small stylesheet for the few pages still rendered
// server-side: the OAuth "you can close this tab" page and nothing else. The
// portal itself is the embedded SPA (web/), which carries its own styles; the
// invite landing (invite_landing.go) is public-facing and keeps its own inline
// styles so it never depends on portal assets.
const portalStyle = `<style>
 body{margin:0;background:#fafaf8;color:#1b2422;font:16px/1.6 system-ui,sans-serif}
 @media (prefers-color-scheme:dark){body{background:#0f1614;color:#e7ece8}}
 main{max-width:760px;margin:0 auto;padding:32px 24px}
</style>`
