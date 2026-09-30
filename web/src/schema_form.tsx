// A form from a JSON Schema — enough of one to drive an MCP tool's inputSchema:
// objects with properties (required marked), strings (enum → select, date-time →
// picker, long → textarea), numbers, booleans, arrays of primitives (one per
// line), and anything else as raw JSON. It never invents fields: what the peer's
// schema does not describe is offered as JSON, so nothing is hidden.
import type { ReactNode } from "react";
import { fieldLabel } from "./words";

export type Schema = {
  type?: string | string[]; properties?: Record<string, Schema>; required?: string[];
  description?: string; title?: string; enum?: unknown[]; format?: string; items?: Schema;
  default?: unknown; minimum?: number; maximum?: number; maxLength?: number;
};

export type Values = Record<string, unknown>;

function typeOf(s: Schema): string {
  const t = Array.isArray(s.type) ? s.type.find((x) => x !== "null") : s.type;
  if (t) return t;
  if (s.properties) return "object";
  if (s.enum) return "string";
  return "unknown";
}

export function SchemaForm({ schema, values, onChange }: { schema: Schema; values: Values; onChange: (v: Values) => void }): ReactNode {
  const props = schema.properties ?? {};
  const required = new Set(schema.required ?? []);
  const names = Object.keys(props);
  if (names.length === 0) {
    // A schema with no field list is not the same as a tool with no arguments:
    // the peer may simply not publish one. Offer raw JSON so the call can still be made.
    return (
      <div className="field">
        <label htmlFor="sf-raw">Arguments <span className="help">— this tool publishes no field list; enter a JSON object, or leave empty for none</span></label>
        <textarea id="sf-raw" rows={3} placeholder="{ }" defaultValue={Object.keys(values).length ? JSON.stringify(values, null, 2) : ""}
          onBlur={(e) => {
            const raw = e.target.value.trim();
            if (!raw) { e.target.setCustomValidity(""); onChange({}); return; }
            try {
              const v = JSON.parse(raw);
              if (v && typeof v === "object" && !Array.isArray(v)) { onChange(v as Values); e.target.setCustomValidity(""); }
              else { e.target.setCustomValidity("must be a JSON object"); e.target.reportValidity(); }
            } catch { e.target.setCustomValidity("not valid JSON"); e.target.reportValidity(); }
          }} />
      </div>
    );
  }
  const set = (k: string, v: unknown) => {
    const next = { ...values };
    if (v === undefined || v === "") delete next[k]; else next[k] = v;
    onChange(next);
  };
  return (
    <div className="sform">
      {names.map((k) => (
        <Field key={k} name={k} schema={props[k]} required={required.has(k)} value={values[k]} onChange={(v) => set(k, v)} />
      ))}
    </div>
  );
}

function Field({ name, schema, required, value, onChange }: {
  name: string; schema: Schema; required: boolean; value: unknown; onChange: (v: unknown) => void;
}) {
  const t = typeOf(schema);
  const id = "sf-" + name.replace(/\W+/g, "_");
  const { text, help } = fieldLabel(name, schema);
  const label = (
    <label htmlFor={id}>{text}{required && <span className="req"> *</span>}
      {text !== name && <code className="sf-key" title="The field's name in the tool's schema">{name}</code>}
      {help && <span className="help"> — {help}</span>}
    </label>
  );
  if (schema.enum) {
    return (
      <div className="field">{label}
        <select id={id} value={value === undefined ? "" : String(value)} onChange={(e) => onChange(e.target.value === "" ? undefined : coerceEnum(schema, e.target.value))}>
          <option value="">{required ? "choose…" : "(none)"}</option>
          {schema.enum.map((o) => <option key={String(o)} value={String(o)}>{String(o)}</option>)}
        </select>
      </div>
    );
  }
  if (t === "boolean") {
    return (
      <div className="field">
        <label className="inline" htmlFor={id}>
          <input id={id} type="checkbox" checked={Boolean(value)} onChange={(e) => onChange(e.target.checked ? true : undefined)} />
          {text}{text !== name && <code className="sf-key" title="The field's name in the tool's schema">{name}</code>}{help && <span className="help"> — {help}</span>}
        </label>
      </div>
    );
  }
  if (t === "number" || t === "integer") {
    return (
      <div className="field">{label}
        <input id={id} type="number" step={t === "integer" ? 1 : "any"} min={schema.minimum} max={schema.maximum}
          value={value === undefined ? "" : String(value)}
          onChange={(e) => onChange(e.target.value === "" ? undefined : t === "integer" ? parseInt(e.target.value, 10) : parseFloat(e.target.value))} />
      </div>
    );
  }
  if (t === "string") {
    if (schema.format === "date-time") {
      return (
        <div className="field">{label}
          <input id={id} type="datetime-local" value={toLocal(value)} onChange={(e) => onChange(e.target.value ? new Date(e.target.value).toISOString() : undefined)} />
        </div>
      );
    }
    const long = (schema.maxLength ?? 0) > 200 || /text|body|notes|message/i.test(name);
    return (
      <div className="field">{label}
        {long
          ? <textarea id={id} rows={3} value={value === undefined ? "" : String(value)} onChange={(e) => onChange(e.target.value)} />
          : <input id={id} type="text" value={value === undefined ? "" : String(value)} onChange={(e) => onChange(e.target.value)} />}
      </div>
    );
  }
  if (t === "array" && schema.items && ["string", "number", "integer"].includes(typeOf(schema.items))) {
    const itemT = typeOf(schema.items);
    const lines = Array.isArray(value) ? (value as unknown[]).map(String).join("\n") : "";
    return (
      <div className="field">{label}
        <textarea id={id} rows={3} placeholder="one per line" value={lines}
          onChange={(e) => {
            const parts = e.target.value.split("\n").map((s) => s.trim()).filter(Boolean);
            onChange(parts.length === 0 ? undefined : itemT === "string" ? parts : parts.map(Number).filter((n) => !Number.isNaN(n)));
          }} />
      </div>
    );
  }
  if (t === "object" && schema.properties) {
    const sub = (value && typeof value === "object" ? (value as Values) : {});
    return (
      <fieldset className="field sub">
        <legend>{text}{required && <span className="req"> *</span>}{text !== name && <code className="sf-key">{name}</code>}</legend>
        {help && <p className="help">{help}</p>}
        <SchemaForm schema={schema} values={sub} onChange={(v) => onChange(Object.keys(v).length ? v : undefined)} />
      </fieldset>
    );
  }
  // Anything else: the schema is shown as-is and the value is typed as JSON.
  return <JSONField id={id} label={label} schema={schema} value={value} onChange={onChange} />;
}

function JSONField({ id, label, schema, value, onChange }: { id: string; label: ReactNode; schema: Schema; value: unknown; onChange: (v: unknown) => void }) {
  const text = value === undefined ? "" : JSON.stringify(value, null, 2);
  return (
    <div className="field">{label}
      <textarea id={id} rows={4} placeholder={"JSON — schema: " + JSON.stringify(schema).slice(0, 120)} defaultValue={text}
        onBlur={(e) => {
          const raw = e.target.value.trim();
          if (!raw) return onChange(undefined);
          try { onChange(JSON.parse(raw)); e.target.setCustomValidity(""); } catch { e.target.setCustomValidity("not valid JSON"); e.target.reportValidity(); }
        }} />
    </div>
  );
}

function coerceEnum(schema: Schema, s: string): unknown {
  const hit = (schema.enum ?? []).find((o) => String(o) === s);
  return hit === undefined ? s : hit;
}

function toLocal(v: unknown): string {
  if (typeof v !== "string" || !v) return "";
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// missingRequired names the required top-level fields not yet filled.
export function missingRequired(schema: Schema, values: Values): string[] {
  return (schema.required ?? []).filter((k) => values[k] === undefined || values[k] === "");
}
