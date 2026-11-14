import { createHash, randomUUID } from 'node:crypto';
import { open, stat, rm, mkdir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { adler32, rollAdler32, packWeak } from './checksum.js';
import { digest } from './archive.js';

export const PROTOCOL_VERSION = 1;
export const WEAK_ALGORITHM = 'adler32';
export const STRONG_ALGORITHM = 'sha256';
export const ALLOWED_BLOCK_SIZES = [8, 16, 64, 256, 1024, 4096];
export const LIT_FLUSH_BYTES = 64 * 1024;

export const FRAME_HEADER = 1;
export const FRAME_LITERAL = 2;
export const FRAME_REF = 3;
export const FRAME_END = 4;

export class DeltaError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'DeltaError';
    this.code = code;
  }
}

function assertSafeInteger(value, label, min = 0) {
  if (!Number.isSafeInteger(value) || value < min) {
    throw new DeltaError('BAD_PROTOCOL', `${label} 不合法`);
  }
}

// 让块索引保持受控（目标块数 256~4096），在协议允许集合中取最小的可行块大小。
export function chooseBlockSize(sourceSize) {
  assertSafeInteger(sourceSize, '文件大小');
  for (const size of [...ALLOWED_BLOCK_SIZES].sort((x, y) => x - y)) {
    if (Math.ceil((sourceSize + 1) / size) <= 256) return size;
  }
  return ALLOWED_BLOCK_SIZES[ALLOWED_BLOCK_SIZES.length - 1];
}

// ---------- 签名：本地旧文件 -> 紧凑二进制协议签名 ----------
//
// 布局：MAGIC(4) | 头JSON长度(4) | 头JSON | 块记录[blockCount]
// 块记录：弱校验 uint32(4) | 长度 uint16(2) | 强摘要前 16 字节(16) = 22 字节
// 每块固定 22 字节，使签名体积随块数线性受控；块偏移由 index*blockSize 推导。
export const SIGNATURE_MAGIC = Buffer.from('DSIG', 'ascii');
const STRONG_PREFIX = 16;
const RECORD_SIZE = 4 + 2 + STRONG_PREFIX;

function signatureHeader(signature) {
  return {
    protocolVersion: PROTOCOL_VERSION,
    blockSize: signature.blockSize,
    weak: WEAK_ALGORITHM,
    strong: STRONG_ALGORITHM,
    strongPrefixBytes: STRONG_PREFIX,
    baseSize: signature.baseSize,
    baseSha256: signature.baseSha256,
    blockCount: signature.blockCount,
  };
}

// 强摘要只取前 16 字节（128 位）进入索引：足以裁决弱碰撞，又把签名体积压到 22B/块。
function strongPrefix(hex) {
  return Buffer.from(hex.slice(0, STRONG_PREFIX * 2), 'hex');
}

export function encodeSignature(signature) {
  validateSignature(signature);
  const headerJson = Buffer.from(JSON.stringify(signatureHeader(signature)), 'utf8');
  const out = Buffer.alloc(8 + headerJson.length + signature.blockCount * RECORD_SIZE);
  SIGNATURE_MAGIC.copy(out, 0);
  out.writeUInt32BE(headerJson.length, 4);
  headerJson.copy(out, 8);
  let cursor = 8 + headerJson.length;
  for (const entry of signature.blocks) {
    out.writeUInt32BE(entry.weak, cursor);
    out.writeUInt16BE(entry.length, cursor + 4);
    strongPrefix(entry.strong).copy(out, cursor + 6);
    cursor += RECORD_SIZE;
  }
  return out;
}

export function parseSignature(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 8 || !bytes.subarray(0, 4).equals(SIGNATURE_MAGIC)) {
    throw new DeltaError('BAD_SIGNATURE', '签名魔数不正确');
  }
  const headerLength = bytes.readUInt32BE(4);
  if (headerLength === 0 || 8 + headerLength > bytes.length) {
    throw new DeltaError('BAD_SIGNATURE', '签名头部长度越界');
  }
  let header;
  try { header = JSON.parse(bytes.subarray(8, 8 + headerLength).toString('utf8')); }
  catch { throw new DeltaError('BAD_SIGNATURE', '签名头部不是合法 JSON'); }
  const body = bytes.subarray(8 + headerLength);
  if (body.length !== header.blockCount * RECORD_SIZE) {
    throw new DeltaError('BAD_SIGNATURE', '签名块记录长度与块数量不符');
  }
  const blocks = [];
  for (let i = 0; i < header.blockCount; i++) {
    const cursor = i * RECORD_SIZE;
    blocks.push({
      index: i,
      offset: i * header.blockSize,
      weak: body.readUInt32BE(cursor),
      length: body.readUInt16BE(cursor + 4),
      strongPrefix: Buffer.from(body.subarray(cursor + 6, cursor + 6 + STRONG_PREFIX)),
    });
  }
  const signature = { ...header, blocks };
  return validateSignature(signature);
}

export function createSignature(base, options = {}) {
  if (!Buffer.isBuffer(base)) throw new DeltaError('BAD_INPUT', '签名基底必须是 Buffer');
  const blockSize = options.blockSize ?? chooseBlockSize(base.length);
  if (!ALLOWED_BLOCK_SIZES.includes(blockSize)) {
    throw new DeltaError('BAD_PROTOCOL', `块大小必须取自 ${ALLOWED_BLOCK_SIZES.join('/')}`);
  }
  const blocks = [];
  for (let offset = 0; offset < base.length; offset += blockSize) {
    const block = base.subarray(offset, Math.min(offset + blockSize, base.length));
    blocks.push({ index: blocks.length, offset, length: block.length,
      weak: adler32(block), strong: digest(block) });
  }
  return {
    protocolVersion: PROTOCOL_VERSION,
    blockSize,
    weak: WEAK_ALGORITHM,
    strong: STRONG_ALGORITHM,
    strongPrefixBytes: STRONG_PREFIX,
    baseSize: base.length,
    baseSha256: digest(base),
    blockCount: blocks.length,
    blocks,
  };
}

// 流式签名：基底按块读取，内存只保留一个块与索引本身。
export async function signFile(basePath, options = {}) {
  const path = resolve(basePath);
  const info = await stat(path);
  if (!info.isFile()) throw new DeltaError('BAD_INPUT', '基底不是普通文件');
  const blockSize = options.blockSize ?? chooseBlockSize(info.size);
  if (!ALLOWED_BLOCK_SIZES.includes(blockSize)) {
    throw new DeltaError('BAD_PROTOCOL', `块大小必须取自 ${ALLOWED_BLOCK_SIZES.join('/')}`);
  }
  const blocks = [];
  const hash = createHash('sha256');
  const handle = await open(path, 'r');
  try {
    let offset = 0;
    while (offset < info.size) {
      const length = Math.min(blockSize, info.size - offset);
      const block = Buffer.allocUnsafe(length);
      const read = (await handle.read(block, 0, length, offset)).bytesRead;
      if (read !== length) throw new DeltaError('BASE_CHANGED', '签名读取不完整，基底可能已被替换');
      hash.update(block);
      blocks.push({ index: blocks.length, offset, length,
        weak: adler32(block), strong: digest(block) });
      offset += length;
    }
  } finally { await handle.close(); }
  return {
    protocolVersion: PROTOCOL_VERSION,
    blockSize,
    weak: WEAK_ALGORITHM,
    strong: STRONG_ALGORITHM,
    strongPrefixBytes: STRONG_PREFIX,
    baseSize: info.size,
    baseSha256: hash.digest('hex'),
    blockCount: blocks.length,
    blocks,
  };
}

export function validateSignature(signature) {
  if (!signature || typeof signature !== 'object') throw new DeltaError('BAD_SIGNATURE', '签名不是对象');
  if (signature.protocolVersion !== PROTOCOL_VERSION) throw new DeltaError('BAD_SIGNATURE', '协议版本不一致');
  if (signature.weak !== WEAK_ALGORITHM || signature.strong !== STRONG_ALGORITHM) {
    throw new DeltaError('BAD_SIGNATURE', '校验算法与协议不一致');
  }
  if (signature.strongPrefixBytes !== STRONG_PREFIX) throw new DeltaError('BAD_SIGNATURE', '强摘要前缀长度不一致');
  if (!ALLOWED_BLOCK_SIZES.includes(signature.blockSize)) throw new DeltaError('BAD_SIGNATURE', '块大小不在协议集合内');
  assertSafeInteger(signature.baseSize, '基底大小');
  if (!/^[a-f0-9]{64}$/.test(signature.baseSha256)) throw new DeltaError('BAD_SIGNATURE', '基底摘要格式不正确');
  if (!Array.isArray(signature.blocks) || signature.blocks.length !== signature.blockCount) {
    throw new DeltaError('BAD_SIGNATURE', '块数量与签名不一致');
  }
  signature.blocks.forEach((entry, index) => {
    if (entry.index !== index || entry.offset !== index * signature.blockSize) {
      throw new DeltaError('BAD_SIGNATURE', '块索引或偏移不一致');
    }
    if (entry.length <= 0 || entry.length > signature.blockSize
      || (index + 1 < signature.blockCount && entry.length !== signature.blockSize)) {
      throw new DeltaError('BAD_SIGNATURE', '块长度不合法');
    }
    assertSafeInteger(entry.weak, '弱校验');
    // 解析后的签名携带二进制前缀；内存签名携带完整 hex，二选一即可。
    if (entry.strongPrefix) {
      if (!Buffer.isBuffer(entry.strongPrefix) || entry.strongPrefix.length !== STRONG_PREFIX) {
        throw new DeltaError('BAD_SIGNATURE', '强摘要前缀长度不正确');
      }
    } else if (!/^[a-f0-9]{64}$/.test(entry.strong)) {
      throw new DeltaError('BAD_SIGNATURE', '强摘要格式不正确');
    }
  });
  return signature;
}

// 弱校验索引：同弱值的块成组保存；重复块取最低 index，弱碰撞由强摘要裁决。
export function buildWeakIndex(signature) {
  const map = new Map();
  for (const entry of signature.blocks) {
    if (!map.has(entry.weak)) map.set(entry.weak, []);
    map.get(entry.weak).push(entry);
  }
  return map;
}

// ---------- 二进制帧：类型(1) + 载荷长度(4) + 载荷 + 长度回写(4) ----------

function frame(type, payload) {
  const out = Buffer.alloc(9 + payload.length);
  out.writeUInt8(type, 0);
  out.writeUInt32BE(payload.length, 1);
  payload.copy(out, 5);
  out.writeUInt32BE(payload.length, 5 + payload.length);
  return out;
}

export function encodeHeaderFrame(header) {
  return frame(FRAME_HEADER, Buffer.from(JSON.stringify(header), 'utf8'));
}

export function encodeLiteralFrame(data) {
  if (!Buffer.isBuffer(data) || data.length === 0) throw new DeltaError('BAD_PROTOCOL', '字面量帧为空');
  return frame(FRAME_LITERAL, data);
}

export function encodeRefFrame(index) {
  const payload = Buffer.alloc(4);
  payload.writeUInt32BE(index, 0);
  return frame(FRAME_REF, payload);
}

export function encodeEndFrame(sha256Hex, size) {
  if (!/^[a-f0-9]{64}$/.test(sha256Hex)) throw new DeltaError('BAD_PROTOCOL', '新文件摘要格式不正确');
  const payload = Buffer.alloc(64 + 8);
  payload.write(sha256Hex, 0, 64, 'utf8');
  payload.writeBigUInt64BE(BigInt(size), 64);
  return frame(FRAME_END, payload);
}

export function headerFor(signature) {
  return {
    protocolVersion: PROTOCOL_VERSION,
    blockSize: signature.blockSize,
    weak: WEAK_ALGORITHM,
    strong: STRONG_ALGORITHM,
    strongPrefixBytes: STRONG_PREFIX,
    baseSize: signature.baseSize,
    baseSha256: signature.baseSha256,
    blockCount: signature.blockCount,
  };
}

// ---------- 帧解码（字面量帧受 maxLiteralBytes 约束） ----------

export async function* parseFrames(iterable, options = {}) {
  const maxLiteral = options.maxLiteralBytes ?? LIT_FLUSH_BYTES;
  const iterator = iterable[Symbol.asyncIterator]?.() ?? iterable[Symbol.iterator]?.();
  if (!iterator) throw new DeltaError('BAD_INPUT', '差量流不可迭代');
  let buffered = Buffer.alloc(0);
  let sawHeader = false;
  let sawEnd = false;

  const pull = async () => {
    const { value, done } = await iterator.next();
    if (done) return false;
    if (!Buffer.isBuffer(value)) throw new DeltaError('BAD_PROTOCOL', '差量流只能包含 Buffer 分块');
    buffered = buffered.length ? Buffer.concat([buffered, value]) : value;
    return true;
  };
  const need = async (n) => {
    while (buffered.length < n) {
      if (!(await pull())) throw new DeltaError('BAD_PROTOCOL', '差量帧被截断');
    }
  };

  while (!sawEnd) {
    await need(5);
    const type = buffered[0];
    const declared = buffered.readUInt32BE(1);
    buffered = buffered.subarray(5);
    await need(declared + 4);
    const payload = buffered.subarray(0, declared);
    if (buffered.readUInt32BE(declared) !== declared) {
      throw new DeltaError('BAD_PROTOCOL', '帧长度首尾不一致');
    }
    buffered = buffered.subarray(declared + 4);

    if (!sawHeader && type !== FRAME_HEADER) throw new DeltaError('BAD_PROTOCOL', '差量流必须以头部帧开始');
    if (type === FRAME_HEADER) {
      let header;
      try { header = JSON.parse(payload.toString('utf8')); }
      catch { throw new DeltaError('BAD_PROTOCOL', '头部帧不是合法 JSON'); }
      sawHeader = true;
      yield { type, header };
    } else if (type === FRAME_LITERAL) {
      if (declared > maxLiteral) throw new DeltaError('BAD_PROTOCOL', '字面量帧超出缓冲区上限');
      yield { type, data: Buffer.from(payload) };
    } else if (type === FRAME_REF) {
      if (declared !== 4) throw new DeltaError('BAD_PROTOCOL', '引用帧载荷长度非法');
      yield { type, index: payload.readUInt32BE(0) };
    } else if (type === FRAME_END) {
      if (declared !== 64 + 8) throw new DeltaError('BAD_PROTOCOL', '结束帧载荷长度非法');
      sawEnd = true;
      yield { type, sha256: payload.subarray(0, 64).toString('utf8'),
        size: Number(payload.readBigUInt64BE(64)) };
    } else {
      throw new DeltaError('BAD_PROTOCOL', `未知帧类型 ${type}`);
    }
  }
}

// ---------- 滚动匹配器（本地模拟远端） ----------
//
// 内存受控：固定环形窗口（<= blockSize）+ 待发字面量（<= litLimit）+ 弱索引。
// ring 为定长环形缓冲，head 指向最旧字节，fill 为有效字节数；窗口填满后 O(1) 滚动。
export class DeltaMatcher {
  constructor(signature, options = {}) {
    validateSignature(signature);
    this.sig = signature;
    this.blockSize = signature.blockSize;
    this.weakIndex = buildWeakIndex(signature);
    this.ring = Buffer.alloc(this.blockSize);
    this.head = 0;
    this.fill = 0;
    this.state = { a: 1, b: 0 };
    this.lit = Buffer.alloc(options.litLimitBytes ?? LIT_FLUSH_BYTES);
    this.litLen = 0;
    this.litLimit = this.lit.length;
    this.pending = [];
    this.targetHash = createHash('sha256');
    this.targetSize = 0;
    this.refs = 0;
    this.literalBytes = 0;
  }

  #emitLiteral() {
    if (this.litLen === 0) return;
    this.pending.push(encodeLiteralFrame(Buffer.from(this.lit.subarray(0, this.litLen))));
    this.literalBytes += this.litLen;
    this.litLen = 0;
  }

  #orderedWindow() {
    if (this.head === 0) return [this.ring.subarray(0, this.fill)];
    return [this.ring.subarray(this.head), this.ring.subarray(0, this.head)];
  }

  #strongPrefixOfWindow() {
    const hash = createHash('sha256');
    for (const part of this.#orderedWindow()) hash.update(part);
    return hash.digest().subarray(0, STRONG_PREFIX);
  }

  #strongMatches(entry, prefix) {
    return entry.strongPrefix ? entry.strongPrefix.equals(prefix)
      : entry.strong.slice(0, STRONG_PREFIX * 2) === prefix.toString('hex');
  }

  #tryMatch() {
    const candidates = this.weakIndex.get(packWeak(this.state.a, this.state.b));
    if (!candidates) return false;
    const prefix = this.#strongPrefixOfWindow();
    const hit = candidates.find(entry => entry.length === this.blockSize && this.#strongMatches(entry, prefix));
    if (!hit) return false; // 弱校验碰撞被强摘要否决，窗口继续滚动为字面量
    this.#emitLiteral();
    this.pending.push(encodeRefFrame(hit.index));
    this.refs += 1;
    this.head = 0;
    this.fill = 0;
    this.state = { a: 1, b: 0 };
    return true;
  }

  push(chunk) {
    if (!Buffer.isBuffer(chunk)) throw new DeltaError('BAD_INPUT', '新文件分块必须是 Buffer');
    this.targetHash.update(chunk);
    this.targetSize += chunk.length;
    for (const byte of chunk) {
      if (this.fill < this.blockSize) {
        this.ring[this.fill] = byte;
        this.fill += 1;
        if (this.fill === this.blockSize) {
          this.state = { a: 1, b: 0 };
          for (let i = 0; i < this.blockSize; i++) {
            this.state.a = (this.state.a + this.ring[i]) % 65521;
            this.state.b = (this.state.b + this.state.a) % 65521;
          }
          this.#tryMatch();
        }
      } else {
        const out = this.ring[this.head];
        this.ring[this.head] = byte;
        this.head = (this.head + 1) % this.blockSize;
        this.state = rollAdler32(this.state, out, byte, this.blockSize);
        // 滑出窗口的最旧字节进入字面量区
        this.lit[this.litLen++] = out;
        if (this.litLen >= this.litLimit) this.#emitLiteral();
        this.#tryMatch();
      }
    }
    const frames = this.pending;
    this.pending = [];
    return frames;
  }

  finish() {
    // 尾部短块：与签名中的等长短块（通常是基底最后一块）比对。
    if (this.fill > 0 && this.fill < this.blockSize) {
      const tail = Buffer.concat(this.#orderedWindow());
      const prefix = createHash('sha256').update(tail).digest().subarray(0, STRONG_PREFIX);
      const candidates = this.weakIndex.get(adler32(tail)) ?? [];
      const hit = candidates.find(entry => entry.length === tail.length && this.#strongMatches(entry, prefix));
      if (hit) {
        this.#emitLiteral();
        this.pending.push(encodeRefFrame(hit.index));
        this.refs += 1;
        this.fill = 0;
      }
    }
    if (this.fill > 0) {
      for (const part of this.#orderedWindow()) {
        part.copy(this.lit, this.litLen);
        this.litLen += part.length;
      }
    }
    this.#emitLiteral();
    this.pending.push(encodeEndFrame(this.targetHash.digest('hex'), this.targetSize));
    const frames = this.pending;
    this.pending = [];
    return frames;
  }
}

// 从 Buffer 或异步分块迭代器生成差量帧；expectedSize 用于远端版本守卫。
export async function* createDelta(signature, target, options = {}) {
  validateSignature(signature);
  yield encodeHeaderFrame(headerFor(signature));
  const matcher = new DeltaMatcher(signature, options);
  if (Buffer.isBuffer(target)) {
    yield* matcher.push(target);
    yield* matcher.finish();
  } else if (target && typeof target[Symbol.asyncIterator] === 'function') {
    for await (const chunk of target) yield* matcher.push(chunk);
    yield* matcher.finish();
  } else {
    throw new DeltaError('BAD_INPUT', '新文件必须是 Buffer 或异步分块迭代器');
  }
  if (options.expectedSize !== undefined && matcher.targetSize !== options.expectedSize) {
    throw new DeltaError('REMOTE_CHANGED', '新文件大小与声明不一致，远端版本可能已变化');
  }
}

// 文件版生成：生成期间远端文件大小/inode 变化即中止，绝不继续拼接。
export async function* deltaFramesFromFile(signature, targetPath, options = {}) {
  validateSignature(signature);
  const path = resolve(targetPath);
  const before = await stat(path);
  if (!before.isFile()) throw new DeltaError('BAD_INPUT', '新文件不是普通文件');
  yield encodeHeaderFrame(headerFor(signature));
  const matcher = new DeltaMatcher(signature, options);
  const handle = await open(path, 'r');
  try {
    const readSize = Math.max(signature.blockSize * 1024, 64 * 1024);
    const buffer = Buffer.allocUnsafe(readSize);
    let offset = 0;
    while (offset < before.size) {
      const length = Math.min(readSize, before.size - offset);
      const read = (await handle.read(buffer, 0, length, offset)).bytesRead;
      if (read !== length) throw new DeltaError('REMOTE_CHANGED', '新文件读取不完整，远端版本已变化');
      yield* matcher.push(buffer.subarray(0, read));
      offset += read;
    }
    const after = await stat(path);
    if (after.size !== before.size || after.ino !== before.ino) {
      throw new DeltaError('REMOTE_CHANGED', '生成期间远端版本发生变化');
    }
    yield* matcher.finish();
  } finally {
    await handle.close();
  }
}

// ---------- 流式重建 ----------

async function verifyBaseFile(handle, expectedSize, expectedSha256) {
  const info = await handle.stat();
  if (info.size !== expectedSize) {
    throw new DeltaError('BASE_MISMATCH', '本地基底大小与签名不一致，引用不可信');
  }
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(64 * 1024);
  let offset = 0;
  while (offset < info.size) {
    const length = Math.min(buffer.length, info.size - offset);
    const read = (await handle.read(buffer, 0, length, offset)).bytesRead;
    if (read !== length) throw new DeltaError('BASE_CHANGED', '基底读取不完整');
    hash.update(buffer.subarray(0, read));
    offset += read;
  }
  if (hash.digest('hex') !== expectedSha256) {
    throw new DeltaError('BASE_MISMATCH', '本地基底摘要与签名不一致，引用不可信');
  }
  return info;
}

// 重建到独立暂存文件；整份新文件摘要核验通过前绝不触碰基底、绝不对外可见。
export async function reconstruct(signature, deltaIterable, basePath, options = {}) {
  validateSignature(signature);
  const base = resolve(basePath);
  const workdir = resolve(options.workdir ?? dirname(base));
  await mkdir(workdir, { recursive: true });
  const stagingPath = join(workdir, `delta-${randomUUID()}.tmp`);

  const baseHandle = await open(base, 'r');
  let outHandle;
  let identity;
  try {
    identity = await verifyBaseFile(baseHandle, signature.baseSize, signature.baseSha256);
    outHandle = await open(stagingPath, 'wx', 0o600);

    const outputHash = createHash('sha256');
    let outputSize = 0;
    let refs = 0;
    let literalBytes = 0;
    let wireBytes = 0;
    let endFrame;
    const refBuffer = Buffer.allocUnsafe(signature.blockSize);

    const counting = (async function* () {
      for await (const chunk of deltaIterable) {
        wireBytes += chunk.length;
        yield chunk;
      }
    })();

    for await (const frame of parseFrames(counting, options)) {
      if (frame.type === FRAME_HEADER) {
        const h = frame.header;
        const checks = [
          [h.protocolVersion === PROTOCOL_VERSION, '协议版本'],
          [h.blockSize === signature.blockSize, '块大小'],
          [h.weak === WEAK_ALGORITHM, '弱校验算法'],
          [h.strong === STRONG_ALGORITHM, '强摘要算法'],
          [h.strongPrefixBytes === STRONG_PREFIX, '强摘要前缀长度'],
          [h.baseSize === signature.baseSize, '基底大小'],
          [h.baseSha256 === signature.baseSha256, '旧文件身份'],
          [h.blockCount === signature.blockCount, '块数量'],
        ];
        const failed = checks.find(([ok]) => !ok);
        if (failed) throw new DeltaError('BAD_PROTOCOL', `差量头部${failed[1]}与签名不一致`);
      } else if (frame.type === FRAME_LITERAL) {
        await outHandle.writeFile(frame.data);
        outputHash.update(frame.data);
        outputSize += frame.data.length;
        literalBytes += frame.data.length;
      } else if (frame.type === FRAME_REF) {
        if (frame.index >= signature.blockCount) {
          throw new DeltaError('BAD_PROTOCOL', '引用块索引超出签名范围');
        }
        // 每次引用前复核基底身份；基底被替换则已收到的引用立即失效。
        const current = await baseHandle.stat();
        if (current.ino !== identity.ino || current.size !== identity.size) {
          throw new DeltaError('BASE_CHANGED', '领取过程中本地基底被替换，引用不再可信');
        }
        const entry = signature.blocks[frame.index];
        const read = (await baseHandle.read(refBuffer, 0, entry.length, entry.offset)).bytesRead;
        if (read !== entry.length) throw new DeltaError('BASE_CHANGED', '引用块读取不完整');
        const prefix = createHash('sha256').update(refBuffer.subarray(0, entry.length))
          .digest().subarray(0, STRONG_PREFIX);
        const expected = entry.strongPrefix ?? Buffer.from(entry.strong.slice(0, STRONG_PREFIX * 2), 'hex');
        if (!expected.equals(prefix)) {
          throw new DeltaError('BASE_MISMATCH', '引用块强摘要不符，基底内容已变化');
        }
        await outHandle.writeFile(refBuffer.subarray(0, entry.length));
        outputHash.update(refBuffer.subarray(0, entry.length));
        outputSize += entry.length;
        refs += 1;
      } else if (frame.type === FRAME_END) {
        endFrame = frame;
      }
    }
    if (!endFrame) throw new DeltaError('BAD_PROTOCOL', '差量流缺少结束帧');
    if (outputSize !== endFrame.size) {
      throw new DeltaError('DIGEST_MISMATCH', `重建大小不符：期望 ${endFrame.size}，实际 ${outputSize}`);
    }
    const outputSha = outputHash.digest('hex');
    if (outputSha !== endFrame.sha256) {
      throw new DeltaError('DIGEST_MISMATCH', '重建文件强摘要与结束帧声明不符');
    }
    // 收尾再复核一次基底身份。
    const finalInfo = await baseHandle.stat();
    if (finalInfo.ino !== identity.ino || finalInfo.size !== identity.size) {
      throw new DeltaError('BASE_CHANGED', '领取结束时基底身份已变化');
    }
    await outHandle.sync();
    await outHandle.close();
    outHandle = undefined;
    return {
      stagingPath,
      sha256: outputSha,
      size: outputSize,
      stats: { refs, literalBytes, wireBytes },
    };
  } catch (error) {
    if (outHandle) await outHandle.close().catch(() => {});
    await rm(stagingPath, { force: true }).catch(() => {});
    throw error;
  } finally {
    await baseHandle.close();
  }
}
