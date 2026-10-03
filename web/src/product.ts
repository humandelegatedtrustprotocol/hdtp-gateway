// Which product this portal is, and where its brand files are: what the node's portal and
// BatonDeck's differ in where they share a view (ui.tsx `Brand`), kept in a file of its own so that
// gateway/scripts/harvest.sh, which copies ui.tsx into the cloud, never carries the node's name across.
export const PRODUCT = {
  /** What the wordmark says, for a reader that cannot see it. */
  name: "HDTP Gateway",
  /** Where the product's brand files are served from: public/brand/, the vendored kit's brand set
   *  (hdtp-web-kit). */
  dir: "brand",
  /** The wordmark's files in that directory: `<logo>-inline.svg` and `-inline-dark.svg`.
   *  web/test/brand_test.mjs holds them to exist, and `width` to the file's own proportions. */
  logo: "hdtp-gateway",
  /** The height the sidebar draws it at, and its width at that height (the file is 84 high), so the layout
   *  holds before it loads. */
  height: 34,
  width: 183,
} as const;
