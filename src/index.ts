export type IntegrityMetadata = HashWithOptions[];

export interface HashWithOptions {
  algorithm: string;
  digest: Uint8Array;
  options: string[];
}

export interface EncodingFns {
  encodeBase64: EncodeBase64Fn;
  decodeBase64: DecodeBase64Fn;
}

export interface EncodeBase64Fn {
  (data: Uint8Array): string;
}

export interface DecodeBase64Fn {
  (data: string): Uint8Array;
}

export interface HashFns {
  sha1?: HashFn;
  sha256?: HashFn;
  sha384?: HashFn;
  sha512?: HashFn;
}

export interface HashFn {
  (data: Uint8Array): Uint8Array;
}

export function parse(
  sri: string,
  decodeBase64: DecodeBase64Fn
): IntegrityMetadata {
  return sri.split(/\s+/).map((hashWithOptions) => {
    const [hash, ...options] = hashWithOptions.split("?");
    const [algorithm, b64] = hash.split("-");
    const digest = decodeBase64(b64 ?? "");
    return { algorithm, digest, options };
  });
}

export function stringify(
  integrity: IntegrityMetadata,
  encodeBase64: EncodeBase64Fn
): string {
  return integrity
    .map(({ algorithm, digest, options }) => {
      const opts = options.map((o) => "?" + o).join("");
      return `${algorithm}-${encodeBase64(digest)}${opts}`;
    })
    .join(" ");
}

export function check(
  hashFns: HashFns,
  integrity: IntegrityMetadata,
  data: Uint8Array
): HashWithOptions | undefined {
  const hash = pickBest(hashFns, integrity);
  if (!hash) throw new Error("There is no suitable hash function.");
  const hashFn = hashFns[hash.algorithm as keyof HashFns]!;
  if (eq(hashFn(data), hash.digest)) return hash;
}

export function pickBest(
  hashFns: HashFns,
  integrity: IntegrityMetadata
): HashWithOptions | undefined {
  const table: { [algorithm in keyof HashFns]: HashWithOptions } = {};
  const availableAlgorithms = priorityTable
    .slice()
    .filter((algorithm) => !!hashFns[algorithm]);
  for (const hash of integrity) table[hash.algorithm as keyof HashFns] = hash;
  for (const algorithm of availableAlgorithms) {
    if (table[algorithm]) return table[algorithm];
  }
  return;
}

const priorityTable: (keyof HashFns)[] = ["sha512", "sha384", "sha256", "sha1"];

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; ++i) if (a[i] !== b[i]) return false;
  return true;
}
