import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createSignature, signFile, encodeSignature, parseSignature, validateSignature,
  createDelta, deltaFramesFromFile, parseFrames, reconstruct, DeltaMatcher,
  chooseBlockSize, DeltaError, FRAME_REF, FRAME_LITERAL, FRAME_HEADER, FRAME_END,
  ALLOWED_BLOCK_SIZES, LIT_FLUSH_BYTES,
} from '../src/delta.js';
import { adler32 } from '../src/checksum.js';
import { digest } from '../src/archive.js';
import { writeFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

async function withTemp(fn) {
  const dir = await mkdtemp(join(tmpdir(), 'delta-test-'));
  try { return await fn(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}

async function collectDelta(signature, target) {
  const frames = [];
  for await (const frame of createDelta(signature, target)) frames.push(frame);
  return frames;
}

async function decode(frames) {
  const events = [];
  for await (const event of parseFrames(frames)) events.push(event);
  return events;
}

test('块大小只取协议集合且随文件规模受控', () => {
  for (const size of [0, 7, 100, 4095, 65536, 5_000_000]) {
    const chosen = chooseBlockSize(size);
    assert.ok(ALLOWED_BLOCK_SIZES.includes(chosen));
    assert.ok(Math.ceil((size + 1) / chosen) <= 256 || chosen === ALLOWED_BLOCK_SIZES.at(-1));
  }
  assert.equal(chooseBlockSize(100), 8);
  assert.equal(chooseBlockSize(4096), 64);
  assert.throws(() => chooseBlockSize(-1), DeltaError);
});

test('签名二进制编码可往返，并保留旧文件身份与块摘要', () => {
  const base = Buffer.from('ABCDE0123456789AB'.repeat(20) + '尾');
  const sig = createSignature(base, { blockSize: 16 });
  const wire = encodeSignature(sig);
  const back = parseSignature(wire);
  assert.equal(back.blockSize, 16);
  assert.equal(back.baseSha256, digest(base));
  assert.equal(back.baseSize, base.length);
  assert.equal(back.blockCount, sig.blockCount);
  assert.equal(back.blocks[0].strongPrefix.length, 16);
  assert.equal(back.blocks.at(-1).length, base.length % 16);
});

test('签名校验拒绝被篡改的头部与块记录', () => {
  const sig = createSignature(Buffer.from('0123456789abcdef'), { blockSize: 8 });
  const wire = encodeSignature(sig);
  assert.ok(parseSignature(wire));
  wire[0] ^= 0xff; // 破坏魔数
  assert.throws(() => parseSignature(wire), /魔数/);
  assert.throws(() => validateSignature({ ...sig, blockSize: 7 }), /块大小/);
  assert.throws(() => validateSignature({ ...sig, baseSha256: 'x'.repeat(64) }), /格式/);
});

test('头部插入一个字节后仍能找到后续全部匹配块，不退化为同偏移分块', async () => {
  const blockSize = 8;
  const unit = Buffer.from('ABCDE0123456789AB'); // 18 字节
  const base = Buffer.concat(Array.from({ length: 50 }, () => unit));
  const target = Buffer.concat([Buffer.from('x'), base]); // 整体错位 1 字节
  const sig = createSignature(base, { blockSize });
  const events = await decode(await collectDelta(sig, target));
  const refs = events.filter(e => e.type === FRAME_REF);
  const literal = events.filter(e => e.type === FRAME_LITERAL)
    .reduce((n, e) => n + e.data.length, 0);
  // 若按同偏移硬切，几乎所有块都会失配；滚动匹配应仍命中绝大多数块。
  assert.ok(refs.length >= sig.blockCount - 2, `仅命中 ${refs.length}/${sig.blockCount}`);
  assert.equal(literal, 1);
  assert.equal(events[0].type, FRAME_HEADER);
  assert.equal(events.at(-1).type, FRAME_END);
  assert.equal(events.at(-1).sha256, digest(target));
});

test('重复块通过引用复用，字面量只覆盖真正不同的区段', async () => {
  const blockSize = 16;
  const pattern = Buffer.from('重复段落-01234567'.repeat(4)); // 64 字节
  const base = Buffer.concat(Array.from({ length: 32 }, () => pattern)); // 2048 字节
  const target = Buffer.concat([
    base.subarray(0, 1024),
    Buffer.from('新增的独有内容########'), // 24 字节
    base.subarray(1024),
  ]);
  const sig = createSignature(base, { blockSize });
  const events = await decode(await collectDelta(sig, target));
  const refs = events.filter(e => e.type === FRAME_REF);
  const literal = events.filter(e => e.type === FRAME_LITERAL)
    .reduce((n, e) => n + e.data.length, 0);
  assert.ok(refs.length >= 100);
  assert.ok(literal <= 24 + blockSize, `字面量异常膨胀：${literal}`);
});

test('尾部短块作为等长引用处理，长度与强摘要双重约束', async () => {
  const blockSize = 16;
  const aligned = '0123456789abcdef'.repeat(3); // 48 字节，块对齐
  const base = Buffer.concat([Buffer.from(aligned), Buffer.from('zz')]); // 50 字节，尾块长 2
  // 改动只发生在一个整块内部，尾部两个字节仍按相同偏移保留
  const target = Buffer.concat([Buffer.from('XY'), base.subarray(2, 48), Buffer.from('zz')]);
  const sig = createSignature(base, { blockSize });
  const events = await decode(await collectDelta(sig, target));
  const refs = events.filter(e => e.type === FRAME_REF);
  assert.ok(refs.length > 0);
  const lastRef = refs.at(-1);
  // 基底尾部短块：长度由签名约束（2），重建时按该长度读取并校验强摘要
  assert.equal(sig.blocks[lastRef.index].length, 2);
  assert.equal(lastRef.index, sig.blockCount - 1);
});

test('弱校验碰撞被强摘要否决：碰撞窗口必须走字面量而非错误引用', async () => {
  const blockSize = 8;
  const a = Buffer.from('ACAAAAAA');
  const b = Buffer.from('BABAAAAA');
  assert.equal(adler32(a), adler32(b)); // 前提：弱碰撞成立
  const sig = createSignature(a, { blockSize });
  const matcher = new DeltaMatcher(sig);
  const frames = [...matcher.push(b), ...matcher.finish()];
  assert.ok(!frames.some(f => f[0] === FRAME_REF), '碰撞窗口不得产生引用');
  // 端到端：含碰撞窗口的文件必须原样重建
  const base = Buffer.concat([a, Buffer.from('01234567'), Buffer.from('tail')]);
  const target = Buffer.concat([b, Buffer.from('01234567'), Buffer.from('tail')]);
  const sig2 = createSignature(base, { blockSize });
  const events = await decode(await collectDelta(sig2, target));
  assert.equal(events.at(-1).sha256, digest(target));
});

test('字面量缓冲受 LIT_FLUSH_BYTES 约束，长失配区段被拆成多帧', async () => {
  const blockSize = 64;
  const base = Buffer.from('A'.repeat(4096));
  const target = Buffer.from('B'.repeat(LIT_FLUSH_BYTES * 2 + 100));
  const sig = createSignature(base, { blockSize });
  const events = await decode(await collectDelta(sig, target));
  const literals = events.filter(e => e.type === FRAME_LITERAL);
  assert.ok(literals.length >= 2);
  for (const event of literals) assert.ok(event.data.length <= LIT_FLUSH_BYTES);
});

test('帧解码器拒绝截断、未知类型与超大字面量', async () => {
  const sig = createSignature(Buffer.from('0123456789abcdef'), { blockSize: 8 });
  const frames = await collectDelta(sig, Buffer.from('xyz'));
  const truncated = frames.slice(0, -1);
  await assert.rejects(decode(truncated), /截断/);

  // 合法头部之后接未知类型帧（载荷长度首尾一致）
  const headerJson = Buffer.from(JSON.stringify({}));
  const headerFrame = Buffer.alloc(9 + headerJson.length);
  headerFrame[0] = FRAME_HEADER;
  headerFrame.writeUInt32BE(headerJson.length, 1);
  headerJson.copy(headerFrame, 5);
  headerFrame.writeUInt32BE(headerJson.length, 5 + headerJson.length);
  const unknownFrame = Buffer.from([9, 0, 0, 0, 0, 0, 0, 0, 0]);
  await assert.rejects(decode([headerFrame, unknownFrame]), /未知帧类型/);

  // 超大字面量帧（声明 1MiB，超过默认上限）
  const bigLength = 1024 * 1024;
  const bigFrame = Buffer.alloc(9 + bigLength + 4);
  bigFrame[0] = FRAME_LITERAL;
  bigFrame.writeUInt32BE(bigLength, 1);
  bigFrame.writeUInt32BE(bigLength, 5 + bigLength); // 首尾长度一致，让检查走到上限判断
  await assert.rejects(decode([headerFrame, bigFrame]), /缓冲区上限/);
});

test('空文件与完全相同文件的边界处理', async () => {
  const sig = createSignature(Buffer.alloc(0), { blockSize: 8 });
  assert.equal(sig.blockCount, 0);
  const events = await decode(await collectDelta(sig, Buffer.alloc(0)));
  assert.equal(events.at(-1).size, 0);
  assert.equal(events.at(-1).sha256, digest(Buffer.alloc(0)));
  const same = Buffer.from('0123456789abcdef');
  const sig2 = createSignature(same, { blockSize: 8 });
  const events2 = await decode(await collectDelta(sig2, same));
  assert.equal(events2.filter(e => e.type === FRAME_REF).length, 2);
});

test('文件版生成与流式重建端到端一致', async (t) => withTemp(async (dir) => {
  const unit = Buffer.from('ABCDE0123456789AB'.repeat(64));
  const base = Buffer.concat(Array.from({ length: 256 }, () => unit));
  const target = Buffer.concat([Buffer.from('x'), base.subarray(0, 100000),
    Buffer.from('###改动###'), base.subarray(100009)]);
  const basePath = join(dir, 'base.bin');
  const targetPath = join(dir, 'new.bin');
  await writeFile(basePath, base);
  await writeFile(targetPath, target);
  const signature = await signFile(basePath);
  const frames = [];
  for await (const frame of deltaFramesFromFile(signature, targetPath)) frames.push(frame);
  const result = await reconstruct(signature, frames, basePath, { workdir: dir });
  try {
    assert.equal(result.sha256, digest(target));
    assert.equal(result.size, target.length);
    assert.ok(result.stats.refs > 0);
  } finally { await rm(result.stagingPath, { force: true }); }
}));

test('远端版本在生成期间变化时拒绝继续拼接', async () => withTemp(async (dir) => {
  const blockSize = 64;
  const base = Buffer.from('A'.repeat(4096));
  const basePath = join(dir, 'base.bin');
  const targetPath = join(dir, 'target.bin');
  await writeFile(basePath, base);
  const original = Buffer.from('B'.repeat(4096));
  await writeFile(targetPath, original);
  const sig = createSignature(base, { blockSize });

  // 文件版：开始生成后、生成器完成 stat 复核前换版（长度变化）
  const consumed = [];
  const generation = (async () => {
    for await (const frame of deltaFramesFromFile(sig, targetPath)) consumed.push(frame);
  })();
  // 等待头部帧产出后改写远端文件
  await new Promise(resolve => setImmediate(resolve));
  await writeFile(targetPath, Buffer.from('C'.repeat(8192)));
  await assert.rejects(generation, /REMOTE_CHANGED|远端版本/);

  // 迭代器版本的长度守卫：声明大小与实际产出不一致
  await writeFile(targetPath, original);
  async function* source() {
    yield original.subarray(0, 2048);
    yield original.subarray(2048);
    await writeFile(targetPath, Buffer.from('D'.repeat(2048)));
  }
  await assert.rejects(
    (async () => {
      for await (const _ of createDelta(sig, source(), { expectedSize: 2048 })) { /* drain */ }
    })(),
    /REMOTE_CHANGED|大小与声明/,
  );
}));
