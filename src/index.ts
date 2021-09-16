export type IntegrityMetadata = HashWithOptions[];

export interface HashWithOptions {
  algorithm: string; // "sha256" | "sha384" | "sha512"
  digest: string; // base64
  options: string[];
}

export function parse(sri: string): IntegrityMetadata {
  return sri.split(/\s+/).map((hashWithOptions) => {
    const [hash, ...options] = hashWithOptions.split("?");
    const [algorithm, b64] = hash.split("-");
    const digest = new TextDecoder().decode(decodeBase64(b64 ?? ""));
    return { algorithm, digest, options };
  });
}

export function stringify(integrity: IntegrityMetadata): string {
  return integrity.map(({ algorithm, digest, options }) => {
    const opts = options.map((o) => "?" + o).join("");
    return `${algorithm}-${encodeBase64(digest)}${opts}`;
  }).join(" ");
}

export async function check(
  subtle: SubtleCrypto,
  integrity: IntegrityMetadata,
  data: Uint8Array,
): Promise<HashWithOptions | undefined> {
  // TODO
  return;
}

export async function digest(
  subtle: SubtleCrypto,
  data: Uint8Array,
  algorithm: string = "sha512",
): Promise<string> {
  // TODO
  return "";
}

// code from https://github.com/denoland/deno_std/blob/main/encoding/base64.ts
const base64abc =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function encodeBase64(data: ArrayBuffer | string): string {
  const uint8 = typeof data === "string"
    ? new TextEncoder().encode(data)
    : data instanceof Uint8Array
    ? data
    : new Uint8Array(data);
  let result = "", i;
  const l = uint8.length;
  for (i = 2; i < l; i += 3) {
    result += base64abc[uint8[i - 2] >> 2];
    result += base64abc[((uint8[i - 2] & 0x03) << 4) | (uint8[i - 1] >> 4)];
    result += base64abc[((uint8[i - 1] & 0x0f) << 2) | (uint8[i] >> 6)];
    result += base64abc[uint8[i] & 0x3f];
  }
  if (i === l + 1) {
    result += base64abc[uint8[i - 2] >> 2];
    result += base64abc[(uint8[i - 2] & 0x03) << 4];
    result += "==";
  }
  if (i === l) {
    result += base64abc[uint8[i - 2] >> 2];
    result += base64abc[((uint8[i - 2] & 0x03) << 4) | (uint8[i - 1] >> 4)];
    result += base64abc[(uint8[i - 1] & 0x0f) << 2];
    result += "=";
  }
  return result;
}
function decodeBase64(b64: string): Uint8Array {
  const binString = atob(b64);
  const size = binString.length;
  const bytes = new Uint8Array(size);
  for (let i = 0; i < size; i++) bytes[i] = binString.charCodeAt(i);
  return bytes;
}
