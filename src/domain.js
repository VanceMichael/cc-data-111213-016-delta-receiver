import { readFile } from 'node:fs/promises';
import { digest } from './archive.js';
import {
  signFile, encodeSignature, parseSignature, deltaFramesFromFile,
  createSignature, createDelta, DeltaError, PROTOCOL_VERSION,
  WEAK_ALGORITHM, STRONG_ALGORITHM, ALLOWED_BLOCK_SIZES,
} from './delta.js';
export const sample = 'fixtures/base.bin';
export const deltaSampleBase = 'fixtures/base.bin';
export const deltaSampleTarget = 'fixtures/new.bin';

export const deltaProtocol = {
  version: PROTOCOL_VERSION,
  weak: WEAK_ALGORITHM,
  strong: STRONG_ALGORITHM,
  strongPrefixBytes: 16,
  operations: ['copy', 'literal'],
  blockSizes: ALLOWED_BLOCK_SIZES,
};

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

// 差量领取的领域入口：签名、差量帧、协议说明均在此登记，CLI 与演示只做编排。
export async function sign(filename, options) {
  const signature = await signFile(filename, options);
  return { signature, wire: encodeSignature(signature) };
}

export function loadSignature(wire) {
  return parseSignature(wire);
}

export async function* deltaFrames(signature, targetPath) {
  yield* deltaFramesFromFile(signature, targetPath);
}

export async function* deltaFramesFromBytes(signature, bytes) {
  yield* createDelta(signature, bytes);
}

export function signatureFromBytes(bytes, options) {
  return createSignature(bytes, options);
}

export { DeltaError };
