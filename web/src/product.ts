// Which product this portal is. The one line the node's portal and PACT Cloud's differ in where they
// share a view (ui.tsx `Brand`), kept in a file of its own so that gateway/scripts/harvest.sh, which
// copies ui.tsx into the cloud, never carries the node's name across.
export const PRODUCT = {
  /** What the wordmark says, for a reader that cannot see it. */
  name: "PACT gateway",
  /** The wordmark's file in public/brand/ (pact-web-kit's brand set): `<logo>-inline.svg` and `-inline-dark.svg`. */
  logo: "pact-gateway",
  /** Its width at the 28px height it is drawn at (the file is 84 high), so the layout holds before it loads. */
  width: 139,
} as const;
