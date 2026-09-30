// Only the rules that catch what the type checker cannot: hooks called after
// an early return (React #310 took the integrations page down twice) and
// effects with stale dependencies.
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";

export default [
  { ignores: ["dist/**", "node_modules/**", "tools/**"] },
  ...tseslint.configs.base ? [tseslint.configs.base] : [],
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: { parser: tseslint.parser, parserOptions: { ecmaFeatures: { jsx: true } } },
    plugins: { "react-hooks": reactHooks },
    rules: { "react-hooks/rules-of-hooks": "error", "react-hooks/exhaustive-deps": "warn" },
  },
  {
    // Views compose the primitives in ui.tsx; they never style ad hoc. A view
    // that needs something the primitives cannot express changes the primitive.
    files: ["src/views/**/*.tsx", "src/app.tsx"],
    rules: {
      "no-restricted-syntax": ["error", {
        selector: "JSXAttribute[name.name='style']",
        message: "No inline styles in views — add or extend a primitive in ui.tsx / style.css.",
      }, {
        // The primitives own these class names. A view that writes one by hand
        // gets whatever the primitive's CSS says, wherever it sits: the inbox's
        // own scroll container was className="list", so the List primitive drew
        // a bordered white card around the conversation pane. Use the component,
        // or give your element a name of its own.
        selector: "JSXAttribute[name.name='className'] > Literal[value=/(^|\\s)(list|card|toolbar|notice|empty|readout|crumb|page-h|menu|menu-item|acts|acts-status)(\\s|$)/]",
        message: "That class belongs to a primitive in ui.tsx — use the component (List, Section, Toolbar, Notice, EmptyState, Readout, Menu) or pick another name.",
      }],
    },
  },
];
