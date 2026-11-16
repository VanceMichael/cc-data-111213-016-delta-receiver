import { createReadStream } from 'node:fs';
import { open, rename, rm, stat } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { digest, hashFile } from './archive.js';

// 差量领取协议（与 fixtures/protocol.json 对应）：
// 签名 = { version, blockSize, weak, strong, basis:{sha256,size}, blocks:[{weak,strong,length}] }
// 差量 = { version, blockSize, weak, strong, basis:{sha256,size}, target:{sha256,size}, ops:[...] }
// 操作 = { op:'copy', index } 引用基底第 index 块 | { op:'literal', data } 字面量字节。
export const PROTOCOL = Object.freeze({
  version: 1, weak: 'adler32', strong: 'sha256', operations: ['copy', 'literal'] });
export const DEFAULT_BLOCK_SIZE = 64;
export const DEFAULT_LITERAL_LIMIT = 64 * 1024;
export const MAX_BLOCK_SIZE = 1024 * 1024;

const MOD = 65521;
const SHA256_HEX = /^[a-f0-9]{64}$/;
const mod = value => ((value % MOD) + MOD) % MOD;

export function assertBlockSize(blockSize) {
  if (!Number.isSafeInteger(blockSize) || blockSize < 1 || blockSize > MAX_BLOCK_SIZE)
    throw new Error('块大小无效');
}

export function weakChecksum(bytes) {
  let a = 1, b = 0;
  for (const byte of bytes) { a += byte; b += a; }
  return mod(b) * 65536 + mod(a);
}

// 滑动窗口弱校验：窗口每前进一个字节用 O(1) 滚动更新，
// 因此插入一个字节后仍能在新偏移处继续命中后续块。
export class RollingChecksum {
  constructor(window) {
    if (!window?.length) throw new Error('滚动窗口不能为空');
    this.length = window.length;
    let a = 1, b = 0;
    for (const byte of window) { a += byte; b += a; }
    this.a = mod(a);
    this.b = mod(b);
  }
  roll(outgoing, incoming) {
    this.a = mod(this.a - outgoing + incoming);
    this.b = mod(this.b - this.length * outgoing + this.a - 1);
    return this.value();
  }
  value() { return this.b * 65536 + this.a; }
}

export function strongChecksum(bytes) { return digest(bytes); }

function blockEntries() { return []; }

export function createSignature(bytes, blockSize = DEFAULT_BLOCK_SIZE) {
  assertBlockSize(blockSize);
  const blocks = blockEntries();
  for (let offset = 0; offset < bytes.length; offset += blockSize) {
    const block = bytes.subarray(offset, offset + blockSize);
    blocks.push({ weak: weakChecksum(block), strong: strongChecksum(block), length: block.length });
  }
  return { version: PROTOCOL.version, blockSize, weak: PROTOCOL.weak, strong: PROTOCOL.strong,
    basis: { sha256: digest(bytes), size: bytes.length }, blocks };
}

// 流式生成签名：按块读取，内存只占一个块。
export async function signFile(path, blockSize = DEFAULT_BLOCK_SIZE) {
  assertBlockSize(blockSize);
  const handle = await open(path, 'r');
  try {
    const { size } = await handle.stat();
    const whole = createHash('sha256');
    const blocks = [];
    const buffer = Buffer.allocUnsafe(blockSize);
    let offset = 0;
    while (offset < size) {
      const wanted = Math.min(blockSize, size - offset);
      const { bytesRead } = await handle.read(buffer, 0, wanted, offset);
      if (bytesRead !== wanted) throw new Error('基底读取不完整');
      const block = buffer.subarray(0, wanted);
      whole.update(block);
      blocks.push({ weak: weakChecksum(block), strong: strongChecksum(block), length: wanted });
      offset += wanted;
    }
    return { version: PROTOCOL.version, blockSize, weak: PROTOCOL.weak, strong: PROTOCOL.strong,
      basis: { sha256: whole.digest('hex'), size }, blocks };
  } finally { await handle.close(); }
}

// 弱校验 -> 候选块号列表。重复块与弱校验碰撞都落在同一列表，
// 逐一比对长度和强摘要后才采纳，索引大小随块数线性受控。
export function buildIndex(signature) {
  const index = new Map();
  signature.blocks.forEach((block, i) => {
    const list = index.get(block.weak);
    if (list) list.push(i); else index.set(block.weak, [i]);
  });
  return index;
}

async function* toChunks(source) {
  if (Buffer.isBuffer(source)) { if (source.length) yield source; return; }
  if (source && typeof source[Symbol.asyncIterator] === 'function') {
    for await (const chunk of source) yield Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    return;
  }
  throw new Error('不支持的目标来源');
}

// 滚动匹配：以异步生成器逐条产出操作。未匹配字节进入定长字面量缓冲，
// 达到 literalLimit 即冲刷；待匹配窗口随块大小受控，与文件总长无关。
export async function* matchOps(signature, source, { literalLimit = DEFAULT_LITERAL_LIMIT } = {}) {
  const { blockSize } = signature;
  assertBlockSize(blockSize);
  if (!Number.isSafeInteger(literalLimit) || literalLimit < 1) throw new Error('字面量缓冲无效');
  const index = buildIndex(signature);
  const it = toChunks(source);
  let pending = Buffer.alloc(0);
  let exhausted = false;
  async function fill(need) {
    while (!exhausted && pending.length < need) {
      const { value, done } = await it.next();
      if (done) { exhausted = true; break; }
      pending = pending.length === 0 ? value : Buffer.concat([pending, value]);
    }
    return pending.length >= need;
  }
  const literalArena = Buffer.allocUnsafe(literalLimit);
  let literalLength = 0;
  let rolling = null;
  while ((await fill(blockSize)) || pending.length > 0) {
    const windowLength = Math.min(blockSize, pending.length);
    let weak;
    if (windowLength === blockSize) {
      if (rolling === null) rolling = new RollingChecksum(pending.subarray(0, blockSize));
      weak = rolling.value();
    } else {
      weak = weakChecksum(pending.subarray(0, windowLength));
    }
    let matched = -1;
    const candidates = index.get(weak);
    if (candidates) {
      const window = pending.subarray(0, windowLength);
      let strong = null;
      for (const i of candidates) {
        const block = signature.blocks[i];
        if (block.length !== windowLength) continue;
        if (strong === null) strong = strongChecksum(window);
        if (block.strong === strong) { matched = i; break; }
      }
    }
    if (matched >= 0) {
      if (literalLength > 0) {
        yield { op: 'literal', data: Buffer.from(literalArena.subarray(0, literalLength)) };
        literalLength = 0;
      }
      yield { op: 'copy', index: matched };
      pending = pending.subarray(windowLength);
      rolling = null;
    } else {
      literalArena[literalLength] = pending[0];
      literalLength += 1;
      if (literalLength === literalLimit) {
        yield { op: 'literal', data: Buffer.from(literalArena) };
        literalLength = 0;
      }
      const outgoing = pending[0];
      const incoming = pending.length > blockSize ? pending[blockSize] : undefined;
      pending = pending.subarray(1);
      if (rolling !== null) {
        if (incoming === undefined) rolling = null;
        else rolling.roll(outgoing, incoming);
      }
    }
    if (pending.byteOffset > literalLimit + 4 * blockSize) pending = Buffer.from(pending);
  }
  if (literalLength > 0)
    yield { op: 'literal', data: Buffer.from(literalArena.subarray(0, literalLength)) };
}

// 模拟远端：先流式核验目标身份写入头部，再滚动匹配产出操作序列。
// 头部同时登记基底身份与新文件摘要，接收方据此决定能否接纳。
export async function createDelta(signature, target, options) {
  let identity, source;
  if (typeof target === 'string') {
    identity = await hashFile(target);
    source = createReadStream(target);
  } else if (Buffer.isBuffer(target)) {
    identity = { sha256: digest(target), size: target.length };
    source = target;
  } else { throw new Error('不支持的目标来源'); }
  const ops = [];
  for await (const op of matchOps(signature, source, options)) ops.push(op);
  return { version: PROTOCOL.version, blockSize: signature.blockSize,
    weak: signature.weak, strong: signature.strong,
    basis: signature.basis, target: identity, ops };
}

export function deltaToJSON(delta) {
  return { version: delta.version, blockSize: delta.blockSize,
    weak: delta.weak, strong: delta.strong, basis: delta.basis, target: delta.target,
    ops: delta.ops.map(op => op.op === 'literal'
      ? { op: 'literal', data: op.data.toString('base64') }
      : { op: 'copy', index: op.index }) };
}

export function deltaFromJSON(json) {
  if (!json || typeof json !== 'object') throw new Error('差量格式不正确');
  return { ...json, ops: json.ops.map(op => {
    if (op.op === 'copy') return { op: 'copy', index: op.index };
    if (op.op === 'literal') return { op: 'literal', data: Buffer.from(op.data, 'base64') };
    throw new Error('未知操作');
  }) };
}

// 差量在链路上的实际字节量（字面量按 base64 计），用于演练对比整份复制。
export function transferredBytes(delta) {
  return Buffer.byteLength(JSON.stringify(deltaToJSON(delta)));
}

function checkIdentity(identity, name) {
  if (!identity || !SHA256_HEX.test(identity.sha256 || '')
    || !Number.isSafeInteger(identity.size) || identity.size < 0)
    throw new Error(`${name}身份登记不完整`);
}

function normalizeLiteral(data) {
  if (Buffer.isBuffer(data)) return data;
  if (typeof data === 'string') return Buffer.from(data, 'base64');
  if (data && data.type === 'Buffer' && Array.isArray(data.data)) return Buffer.from(data.data);
  throw new Error('字面量格式不正确');
}

async function* toOps(ops) {
  if (ops && typeof ops[Symbol.asyncIterator] === 'function') { for await (const op of ops) yield op; return; }
  if (Array.isArray(ops)) { for (const op of ops) yield op; return; }
  throw new Error('差量缺少操作序列');
}

async function hashHandle(handle) {
  const { size } = await handle.stat();
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(Math.min(Math.max(size, 1), 1024 * 1024));
  let offset = 0;
  while (offset < size) {
    const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, size - offset), offset);
    if (bytesRead === 0) throw new Error('基底读取不完整');
    hash.update(buffer.subarray(0, bytesRead));
    offset += bytesRead;
  }
  return { sha256: hash.digest('hex'), size };
}

// 流式重建并原子接纳：
// 1. 打开基底即钉住其身份，领取前核对签名登记的基底摘要；
// 2. 操作序列逐条写入同目录临时文件，同时累计整份摘要，内存只占块缓冲；
// 3. 整份摘要等于头部登记的新文件摘要、且基底在领取期间未被替换，才原子改名覆盖输出。
// 任一步失败都删除临时文件，失败内容永远不会成为下一次的可信基底。
export async function receiveDelta({ basisPath, delta, outputPath, archive, metadata, onOperation }) {
  if (!delta || typeof delta !== 'object') throw new Error('差量格式不正确');
  if (delta.version !== PROTOCOL.version || delta.weak !== PROTOCOL.weak || delta.strong !== PROTOCOL.strong)
    throw new Error('不支持的差量协议');
  assertBlockSize(delta.blockSize);
  checkIdentity(delta.basis, '基底');
  checkIdentity(delta.target, '目标');
  const basisHandle = await open(basisPath, 'r');
  const temporary = `${outputPath}.${randomUUID()}.tmp`;
  let outputHandle = null;
  try {
    const pinned = await basisHandle.stat();
    const before = await hashHandle(basisHandle);
    if (before.sha256 !== delta.basis.sha256 || before.size !== delta.basis.size)
      throw new Error('本地基底与签名身份不符，拒绝使用其块引用');
    outputHandle = await open(temporary, 'wx', 0o600);
    const hash = createHash('sha256');
    const blockBuffer = Buffer.allocUnsafe(delta.blockSize);
    const blockCount = Math.ceil(delta.basis.size / delta.blockSize);
    let written = 0, literalBytes = 0, copyBlocks = 0;
    for await (const op of toOps(delta.ops)) {
      if (op.op === 'copy') {
        const { index } = op;
        if (!Number.isSafeInteger(index) || index < 0 || index >= blockCount)
          throw new Error(`块引用越界: ${index}`);
        const length = Math.min(delta.blockSize, delta.basis.size - index * delta.blockSize);
        const { bytesRead } = await basisHandle.read(blockBuffer, 0, length, index * delta.blockSize);
        if (bytesRead !== length) throw new Error('基底读取不完整');
        const slice = blockBuffer.subarray(0, length);
        hash.update(slice);
        await outputHandle.write(slice);
        written += length;
        copyBlocks += 1;
      } else if (op.op === 'literal') {
        const data = normalizeLiteral(op.data);
        hash.update(data);
        await outputHandle.write(data);
        written += data.length;
        literalBytes += data.length;
      } else { throw new Error('未知操作'); }
      if (onOperation) await onOperation(op, { written });
    }
    const after = await hashHandle(basisHandle);
    const now = await stat(basisPath);
    if (after.sha256 !== before.sha256 || now.ino !== pinned.ino
      || now.size !== pinned.size || now.mtimeMs !== pinned.mtimeMs)
      throw new Error('本地基底在领取期间被替换，已收到的块引用不可信');
    if (written !== delta.target.size)
      throw new Error(`重建长度 ${written} 与目标登记 ${delta.target.size} 不符`);
    if (hash.digest('hex') !== delta.target.sha256)
      throw new Error('重建结果与远端版本摘要不符，拒绝接纳');
    await outputHandle.sync();
    await outputHandle.close();
    outputHandle = null;
    await rename(temporary, outputPath);
    const stats = { sha256: delta.target.sha256, size: written,
      literalBytes, copyBlocks, transferredBytes: transferredBytes(delta) };
    let receipt = null;
    if (archive) {
      receipt = await archive.acceptFile(outputPath,
        { ...metadata, basis: delta.basis, transfer: stats },
        { expectedSha256: delta.target.sha256 });
    }
    return { outputPath, ...stats, receipt };
  } finally {
    if (outputHandle) await outputHandle.close();
    await basisHandle.close();
    await rm(temporary, { force: true });
  }
}
