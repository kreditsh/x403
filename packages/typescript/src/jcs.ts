// RFC 8785 (JSON Canonicalization Scheme). Every hash and every signature in x403 is over
// this form, so two implementations that agree here agree everywhere.

import type { Hash } from "./types.js";

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

function serialize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new TypeError("JCS: non-finite number");
      // ES6 Number::toString is exactly the RFC 8785 number form; 0 and -0 both print as 0.
      return Object.is(value, -0) ? "0" : String(value);
    case "string":
      // JSON.stringify escapes only what RFC 8785 escapes, with lowercase \u00xx.
      return JSON.stringify(value);
    case "bigint":
      throw new TypeError("JCS: bigint is not JSON");
    case "undefined":
      throw new TypeError("JCS: undefined is not JSON");
    case "object": {
      if (Array.isArray(value)) return "[" + value.map((v) => serialize(v === undefined ? null : v)).join(",") + "]";
      const obj = value as Record<string, unknown>;
      // Default sort compares UTF-16 code units, which is what the RFC asks for.
      const keys = Object.keys(obj)
        .filter((k) => obj[k] !== undefined)
        .sort();
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + serialize(obj[k])).join(",") + "}";
    }
    default:
      throw new TypeError(`JCS: cannot serialize ${typeof value}`);
  }
}

/** The canonical JSON text of a value. */
export function canonicalize(value: unknown): string {
  return serialize(value as Json);
}

const encoder = new TextEncoder();

export function utf8(text: string): Uint8Array {
  return encoder.encode(text);
}

export function hex(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = "";
  for (const b of view) out += b.toString(16).padStart(2, "0");
  return out;
}

export async function sha256(data: Uint8Array | string): Promise<Uint8Array> {
  const bytes = typeof data === "string" ? utf8(data) : data;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource));
}

/** `sha256:<hex>` of the canonical form of an object. */
export async function hash(value: unknown): Promise<Hash> {
  return `sha256:${hex(await sha256(canonicalize(value)))}`;
}

/** `sha256:<hex>` of a string as given: a JWT, an SD-JWT, any opaque artifact. */
export async function hashString(text: string): Promise<Hash> {
  return `sha256:${hex(await sha256(text))}`;
}
