// Which product this portal is. The one line the node's portal and BatonDeck's differ in where they
// share a view (ui.tsx `Brand`), kept in a file of its own so that gateway/scripts/harvest.sh, which
// copies ui.tsx into the cloud, never carries the node's name across.
export const PRODUCT = {
  /** What the wordmark says, for a reader that cannot see it. */
  name: "HDTP Gateway",
  /** The wordmark's file in public/brand/ (hdtp-web-kit's brand set): `<logo>-inline.svg` and `-inline-dark.svg`. */
  logo: "pact-gateway",
  /** The height the sidebar draws it at, and its width at that height (the file is 84 high), so the layout
   *  holds before it loads. */
  height: 34,
  width: 169,
} as const;
