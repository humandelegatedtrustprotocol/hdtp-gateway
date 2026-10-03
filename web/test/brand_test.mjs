// The wordmark the portal asks for is a file that is there, at the size the layout reserves for it.
//
// product.ts names the product's brand files (`dir`, `logo`) and the box the sidebar reserves
// (`width`, `height`); ui.tsx's `Brand` asks the browser for them; and the pages the Go server writes
// itself (internal/internalui: style.go, wallet_pages.go) ask for the same files by a path and a size
// of their own. None of that was held to the files: a wordmark renamed in the kit, or redrawn at
// another width, left every test green with the image missing or squeezed. The kit's check
// (web/tools/kit.mjs) holds the files to the release; this holds what asks for them to the files.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PRODUCT } from "../src/product.ts";

const WEB = join(dirname(fileURLToPath(import.meta.url)), "..");
const REPO = join(WEB, "..");
const PUBLIC = join(WEB, "public");

/** An SVG file's own size, from its root element. */
function sizeOf(file) {
  const m = /<svg\b[^>]*\bwidth="([\d.]+)"[^>]*\bheight="([\d.]+)"/.exec(readFileSync(file, "utf8"));
  assert.ok(m, `${file} states no width and height`);
  return { width: Number(m[1]), height: Number(m[2]) };
}

/** The width a file takes when it is drawn `height` high. */
const widthAt = (file, height) => { const s = sizeOf(file); return Math.round((height * s.width) / s.height); };

test("the product's wordmark files are there, light and dark", () => {
  for (const name of [`${PRODUCT.logo}-inline.svg`, `${PRODUCT.logo}-inline-dark.svg`]) {
    assert.ok(existsSync(join(PUBLIC, PRODUCT.dir, name)), `public/${PRODUCT.dir}/${name} is not a file`);
  }
});

test("the box the sidebar reserves is the wordmark's own proportion", () => {
  for (const name of [`${PRODUCT.logo}-inline.svg`, `${PRODUCT.logo}-inline-dark.svg`]) {
    assert.equal(PRODUCT.width, widthAt(join(PUBLIC, PRODUCT.dir, name), PRODUCT.height), `product.ts width, against ${name} at height ${PRODUCT.height}`);
  }
});

test("Brand asks for the files product.ts names, and for no other path", () => {
  const ui = readFileSync(join(WEB, "src", "ui.tsx"), "utf8");
  const brand = /export function Brand\(\)[\s\S]*?\n}\n/.exec(ui);
  assert.ok(brand, "ui.tsx has no Brand component");
  const asked = [...brand[0].matchAll(/(?:srcSet|src)=\{`([^`]+)`\}/g)].map((m) => m[1]).sort();
  assert.deepEqual(asked, ["/${PRODUCT.dir}/${PRODUCT.logo}-inline-dark.svg", "/${PRODUCT.dir}/${PRODUCT.logo}-inline.svg"]);
});

test("the server's own pages ask for brand files that are there, at their proportion", () => {
  let images = 0, files = 0;
  for (const source of ["internal/internalui/style.go", "internal/internalui/wallet_pages.go"]) {
    const go = readFileSync(join(REPO, source), "utf8");
    // Every brand path a page names, in an attribute.
    for (const m of go.matchAll(/(?:src|srcset|href)="(\/brand\/[^"]+)"/g)) {
      files++;
      assert.ok(existsSync(join(PUBLIC, m[1])), `${source} asks for ${m[1]}, which is not a file in public/`);
    }
    // Every image that reserves a box for one.
    for (const m of go.matchAll(/<img\b[^>]*\bsrc="(\/brand\/[^"]+\.svg)"[^>]*\bwidth="(\d+)"[^>]*\bheight="(\d+)"/g)) {
      images++;
      assert.equal(Number(m[2]), widthAt(join(PUBLIC, m[1]), Number(m[3])), `${source}: the width reserved for ${m[1]} at height ${m[3]}`);
    }
  }
  // A reader that found nothing holds nothing: the two pages draw the wordmark, light and dark.
  assert.ok(images >= 2 && files >= 5, `read ${images} sized images and ${files} brand paths out of the server's pages`);
});
