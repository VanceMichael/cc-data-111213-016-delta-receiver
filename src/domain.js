import { readFile } from 'node:fs/promises';
import { digest } from './archive.js';
export const sample = 'fixtures/base.bin';
export function fixedBlocks(bytes, blockSize = 16) {
  if (!Number.isSafeInteger(blockSize) || blockSize < 1) throw new Error('块大小无效');
  const result = [];
  for (let offset = 0; offset < bytes.length; offset += blockSize) {
    const block = bytes.subarray(offset, offset + blockSize);
    result.push({ offset, length: block.length, sha256: digest(block) });
  }
  return result;
}
export async function inspect(filename) {
  const bytes = await readFile(filename);
  return { size: bytes.length, sha256: digest(bytes), blocks: fixedBlocks(bytes) };
}
