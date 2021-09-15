export type IntegrityMetadata = HashWithOptions[];

export interface HashWithOptions {
  algorithm: string;
  digest: string;
  options: string[];
}

export function parse(sri: string): IntegrityMetadata {
  // TODO
  return [];
}

export function stringify(integrity: IntegrityMetadata): string {
  // TODO
  return "";
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
