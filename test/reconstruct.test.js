import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, writeFile, mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSignature, createDelta, reconstruct, DeltaError } from '../src/delta.js';
import { Archive } from '../src/archive.js';
import { digest } from '../src/archive.js';

async function withTemp(fn) {
  const dir = await mkdtemp(join(tmpdir(), 'reconstruct-test-'));
  try { return await fn(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}

async function deltaFrames(signature, target) {
  const frames = [];
  for await (const frame of createDelta(signature, target)) frames.push(frame);
  return frames;
}

test('整份摘要核验通过前输出只存在于隔离暂存件，且不覆盖基底', async () => withTemp(async (dir) => {
  const base = Buffer.from('基线内容-0123456789'.repeat(128));
  const target = Buffer.concat([Buffer.from('头部插入'), base.subarray(6)]);
  const basePath = join(dir, 'base.bin');
  await writeFile(basePath, base);
  const sig = createSignature(base, { blockSize: 16 });
  const result = await reconstruct(sig, await deltaFrames(sig, target), basePath, { workdir: dir });
  try {
    assert.notEqual(result.stagingPath, basePath);
    assert.ok(result.stagingPath.endsWith('.tmp'));
    // 基底原封不动
    assert.ok((await readFile(basePath)).equals(base));
    const rebuilt = await readFile(result.stagingPath);
    assert.ok(rebuilt.equals(target));
    assert.equal(result.sha256, digest(target));
  } finally { await rm(result.stagingPath, { force: true }); }
}));

test('基底在领取前被替换（同大小不同内容）时拒绝且不产生暂存残留', async () => withTemp(async (dir) => {
  const base = Buffer.from('基线内容-0123456789'.repeat(128));
  const target = Buffer.concat([Buffer.from('新'), base.subarray(1)]);
  const basePath = join(dir, 'base.bin');
  await writeFile(basePath, base);
  const sig = createSignature(base, { blockSize: 16 });
  const frames = await deltaFrames(sig, target);
  // 签名生成后、重建前替换基底（保持大小一致，绕过单纯的尺寸检查）
  const swapped = Buffer.from('X'.repeat(base.length));
  await writeFile(basePath, swapped);
  await assert.rejects(reconstruct(sig, frames, basePath, { workdir: dir }),
    (error) => error instanceof DeltaError && error.code === 'BASE_MISMATCH');
  const leftovers = (await readdir(dir)).filter(name => name.endsWith('.tmp'));
  assert.deepEqual(leftovers, []);
}));

test('基底大小变化时以 BASE_MISMATCH 拒绝，已收到的引用全部作废', async () => withTemp(async (dir) => {
  const base = Buffer.from('基线内容-0123456789'.repeat(128));
  const target = base;
  const basePath = join(dir, 'base.bin');
  await writeFile(basePath, base);
  const sig = createSignature(base, { blockSize: 16 });
  const frames = await deltaFrames(sig, target);
  await writeFile(basePath, Buffer.concat([base, Buffer.from('额外字节')]));
  await assert.rejects(reconstruct(sig, frames, basePath, { workdir: dir }),
    (error) => error.code === 'BASE_MISMATCH');
}));

test('损坏的差量流（错误结束帧摘要）导致重建失败并清理', async () => withTemp(async (dir) => {
  const base = Buffer.from('基线内容-0123456789'.repeat(128));
  const target = Buffer.concat([Buffer.from('改动'), base.subarray(2)]);
  const basePath = join(dir, 'base.bin');
  await writeFile(basePath, base);
  const sig = createSignature(base, { blockSize: 16 });
  const frames = await deltaFrames(sig, target);
  // 篡改最后一个结束帧里的摘要
  const last = frames.at(-1);
  last[5] = last[5] === 97 ? 98 : 97;
  await assert.rejects(reconstruct(sig, frames, basePath, { workdir: dir }),
    (error) => error.code === 'DIGEST_MISMATCH');
  assert.deepEqual((await readdir(dir)).filter(n => n.endsWith('.tmp')), []);
}));

test('引用越界与头部身份不符都被协议层拒绝', async () => withTemp(async (dir) => {
  const base = Buffer.from('0123456789abcdef'.repeat(32));
  const basePath = join(dir, 'base.bin');
  await writeFile(basePath, base);
  const sig = createSignature(base, { blockSize: 16 });
  const frames = await deltaFrames(sig, base);
  // 把某个引用帧的索引改到范围外
  const refFrame = frames.find(f => f[0] === 3);
  // 帧布局：类型(1)+载荷长度(4)+索引(4)+长度回写(4)；只改索引，保持帧结构合法
  refFrame.writeUInt32BE(99999, 5);
  await assert.rejects(reconstruct(sig, frames, basePath, { workdir: dir }), /索引超出/);

  const foreign = { ...sig, baseSha256: 'a'.repeat(64) };
  // 基底身份与签名不符在开工核验阶段即被拦截，引用不会被使用
  await assert.rejects(reconstruct(foreign, await deltaFrames(sig, base), basePath, { workdir: dir }),
    (error) => error.code === 'BASE_MISMATCH');

  // 基底真实且与签名一致，但差量头部声明的旧文件身份与签名不符
  const goodFrames = await deltaFrames(sig, base);
  const header = JSON.parse(goodFrames[0].subarray(5, 5 + goodFrames[0].readUInt32BE(1)).toString('utf8'));
  header.baseSha256 = 'b'.repeat(64);
  const json = Buffer.from(JSON.stringify(header), 'utf8');
  goodFrames[0] = Buffer.concat([
    Buffer.from([1]),
    (() => { const b = Buffer.alloc(4); b.writeUInt32BE(json.length, 0); return b; })(),
    json,
    (() => { const b = Buffer.alloc(4); b.writeUInt32BE(json.length, 0); return b; })(),
  ]);
  await assert.rejects(reconstruct(sig, goodFrames, basePath, { workdir: dir }), /旧文件身份/);
}));

test('归档接纳：成功才登记回执，失败的暂存件不会成为下一次可信基底', async () => withTemp(async (dir) => {
  const archiveDir = join(dir, 'archive');
  const archive = new Archive(archiveDir);
  const base = Buffer.from('归档基线-0123456789'.repeat(256));
  const target = Buffer.concat([Buffer.from('头部新增内容'), base.subarray(12)]);
  const basePath = join(dir, 'base.bin');
  await writeFile(basePath, base);
  const sig = createSignature(base, { blockSize: 16 });

  const receipt = await archive.acceptDelta(sig, await deltaFrames(sig, target), basePath,
    { source: '合作方甲' });
  assert.equal(receipt.mode, 'delta');
  assert.equal(receipt.sha256, digest(target));
  assert.equal(receipt.baseSha256, digest(base));
  assert.ok(receipt.transfer.refs > 0);
  assert.ok((await archive.read(receipt.sha256)).equals(target));

  // 失败一次：基底被篡改
  const target2 = Buffer.concat([Buffer.from('第二轮'), base.subarray(6)]);
  await writeFile(basePath, Buffer.from('Z'.repeat(base.length)));
  await assert.rejects(
    archive.acceptDelta(sig, await deltaFrames(sig, target2), basePath, { source: '合作方甲' }),
    (error) => error.code === 'BASE_MISMATCH',
  );
  const staging = await readdir(join(archiveDir, 'staging')).catch(() => []);
  assert.deepEqual(staging, []);
  const receipts = await archive.receipts();
  assert.equal(receipts.length, 1, '失败领取不得登记回执');
  // 对象库中只有第一次成功的对象
  const objects = await readdir(join(archiveDir, 'objects'));
  assert.deepEqual(objects, [receipt.sha256]);

  // 恢复正确基底后重试，应成功——可信基底来自被核验的原文件而非失败暂存件
  await writeFile(basePath, base);
  const retry = await archive.acceptDelta(sig, await deltaFrames(sig, target2), basePath,
    { source: '合作方甲-重试' });
  assert.equal(retry.sha256, digest(target2));
  assert.ok((await archive.read(retry.sha256)).equals(target2));
  assert.equal((await archive.receipts()).length, 2);
}));
