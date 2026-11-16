import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Archive, digest } from '../src/archive.js';
import { createSignature, signFile, matchOps, createDelta, receiveDelta,
  weakChecksum, strongChecksum, RollingChecksum, deltaToJSON, deltaFromJSON,
  transferredBytes, PROTOCOL, DEFAULT_BLOCK_SIZE } from '../src/delta.js';
import { collisionPair, syntheticBytes, drill } from '../src/drill.js';

const fixtures = fileURLToPath(new URL('../fixtures/', import.meta.url));

async function collect(generator) {
  const ops = [];
  for await (const op of generator) ops.push(op);
  return ops;
}

async function withTemp(fn) {
  const folder = await mkdtemp(join(tmpdir(), 'delta-test-'));
  try { return await fn(folder); }
  finally { await rm(folder, { recursive: true, force: true }); }
}

test('滚动弱校验与逐窗重算一致', () => {
  const data = syntheticBytes(5, 1000);
  const size = 64;
  const rolling = new RollingChecksum(data.subarray(0, size));
  assert.equal(rolling.value(), weakChecksum(data.subarray(0, size)));
  for (let i = 0; i + size < data.length; i += 1) {
    const value = rolling.roll(data[i], data[i + size]);
    assert.equal(value, weakChecksum(data.subarray(i + 1, i + 1 + size)));
  }
});

test('弱校验碰撞对：弱校验相同而强摘要不同', () => {
  const [first, second] = collisionPair();
  assert.equal(first.length, DEFAULT_BLOCK_SIZE);
  assert.notDeepEqual(first, second);
  assert.equal(weakChecksum(first), weakChecksum(second));
  assert.notEqual(strongChecksum(first), strongChecksum(second));
});

test('签名登记块大小、弱校验、强摘要与基底身份，尾部短块长度如实', async () => {
  await withTemp(async folder => {
    const bytes = syntheticBytes(3, 1000);
    const path = join(folder, 'basis.bin');
    await writeFile(path, bytes);
    const fromFile = await signFile(path, 64);
    const fromMemory = createSignature(bytes, 64);
    assert.deepEqual(fromFile, fromMemory);
    assert.equal(fromFile.version, PROTOCOL.version);
    assert.equal(fromFile.weak, 'adler32');
    assert.equal(fromFile.strong, 'sha256');
    assert.deepEqual(fromFile.basis, { sha256: digest(bytes), size: bytes.length });
    assert.equal(fromFile.blocks.length, Math.ceil(1000 / 64));
    const tail = fromFile.blocks.at(-1);
    assert.equal(tail.length, 1000 % 64);
    assert.equal(tail.weak, weakChecksum(bytes.subarray(15 * 64)));
    assert.equal(tail.strong, digest(bytes.subarray(15 * 64)));
    assert.throws(() => createSignature(bytes, 0), /块大小无效/);
  });
});

test('头部插入一个字节后仍滚动命中后续块，不退化为同偏移比较', async () => {
  const basis = await readFile(join(fixtures, 'base.bin'));
  const target = await readFile(join(fixtures, 'new.bin'));
  const signature = createSignature(basis, DEFAULT_BLOCK_SIZE);
  const ops = await collect(matchOps(signature, target));
  const copies = ops.filter(op => op.op === 'copy');
  const literalBytes = ops.filter(op => op.op === 'literal')
    .reduce((sum, op) => sum + op.data.length, 0);
  assert.ok(copies.length > 10, `应命中大量块，实际 ${copies.length}`);
  assert.ok(literalBytes < 128, `字面量应很少，实际 ${literalBytes}`);
  const delta = await createDelta(signature, target);
  assert.ok(transferredBytes(delta) < target.length,
    `差量 ${transferredBytes(delta)} 应小于整份 ${target.length}`);
});

test('重复块与尾部短块都能正确重建', async () => {
  await withTemp(async folder => {
    const segment = syntheticBytes(7, 64);
    const basis = Buffer.concat([...Array(9).fill(segment), Buffer.from('尾')]);
    const target = Buffer.concat([...Array(4).fill(segment), Buffer.from('变'),
      ...Array(5).fill(segment), Buffer.from('尾')]);
    const signature = createSignature(basis, 64);
    const delta = await createDelta(signature, target);
    const copies = delta.ops.filter(op => op.op === 'copy');
    assert.ok(copies.some(op => op.index === signature.blocks.length - 1), '尾部短块应被引用');
    const basisPath = join(folder, 'basis.bin');
    const outputPath = join(folder, 'output.bin');
    await writeFile(basisPath, basis);
    const result = await receiveDelta({ basisPath, delta, outputPath });
    assert.equal(result.sha256, digest(target));
    assert.deepEqual(await readFile(outputPath), target);
  });
});

test('弱校验碰撞不产生误配，重建结果仍逐字节正确', async () => {
  await withTemp(async folder => {
    const [alien, resident] = collisionPair();
    const basis = Buffer.concat([resident, syntheticBytes(11, 64), syntheticBytes(13, 64)]);
    const target = Buffer.concat([Buffer.from('前缀:'), alien, resident]);
    const signature = createSignature(basis, DEFAULT_BLOCK_SIZE);
    const delta = await createDelta(signature, target);
    const alienOps = delta.ops.filter(op => op.op === 'literal')
      .reduce((sum, op) => sum + op.data.length, 0);
    assert.ok(alienOps >= alien.length, '碰撞块必须按字面量处理');
    const basisPath = join(folder, 'basis.bin');
    const outputPath = join(folder, 'output.bin');
    await writeFile(basisPath, basis);
    await receiveDelta({ basisPath, delta, outputPath });
    assert.deepEqual(await readFile(outputPath), target);
  });
});

test('差量经 JSON 线格式往返后仍可接收，且接纳写入登记', async () => {
  await withTemp(async folder => {
    const basis = syntheticBytes(17, 3000);
    const target = Buffer.concat([Buffer.from('插入'), basis.subarray(0, 1500),
      syntheticBytes(19, 100), basis.subarray(1500)]);
    const basisPath = join(folder, 'basis.bin');
    const outputPath = join(folder, 'output.bin');
    await writeFile(basisPath, basis);
    const signature = await signFile(basisPath, 64);
    const delta = await createDelta(signature, target);
    const wire = JSON.parse(JSON.stringify(deltaToJSON(delta)));
    const parsed = deltaFromJSON(wire);
    const archive = new Archive(join(folder, 'archive'));
    const result = await receiveDelta({ basisPath, delta: parsed, outputPath,
      archive, metadata: { source: '演练' } });
    assert.equal(result.sha256, digest(target));
    assert.deepEqual(await readFile(outputPath), target);
    const receipts = await archive.receipts();
    assert.equal(receipts.length, 1);
    assert.equal(receipts[0].sha256, digest(target));
    assert.equal(receipts[0].metadata.basis.sha256, digest(basis));
    assert.deepEqual(await archive.read(receipts[0].sha256), target);
  });
});

test('领取途中基底被替换则拒绝接纳，恢复后重试成功，失败残件不可作基底', async () => {
  await withTemp(async folder => {
    const basis = syntheticBytes(29, 4096);
    const target = Buffer.concat([Buffer.from('头'), basis.subarray(0, 2048),
      Buffer.from('—— 改动 ——'), basis.subarray(2048)]);
    const basisPath = join(folder, 'basis.bin');
    const outputPath = join(folder, 'output.bin');
    await writeFile(basisPath, basis);
    const signature = await signFile(basisPath, 64);
    const delta = await createDelta(signature, target);

    let tampered = false;
    const onOperation = async (op, { written }) => {
      if (!tampered && written >= delta.target.size) {
        tampered = true;
        await writeFile(basisPath, syntheticBytes(31, 4096));
      }
    };
    await assert.rejects(receiveDelta({ basisPath, delta, outputPath, onOperation }), /不可信/);
    await assert.rejects(readFile(outputPath));
    const leftovers = (await readdir(folder)).filter(name => name.endsWith('.tmp'));
    assert.deepEqual(leftovers, []);

    await assert.rejects(receiveDelta({ basisPath, delta, outputPath }), /身份不符/);

    await writeFile(basisPath, basis);
    const retry = await receiveDelta({ basisPath, delta, outputPath });
    assert.equal(retry.sha256, digest(target));
    assert.deepEqual(await readFile(outputPath), target);
  });
});

test('远端版本变化或差量被篡改都不能拼接纳管', async () => {
  await withTemp(async folder => {
    const basis = syntheticBytes(37, 2048);
    const target = Buffer.concat([Buffer.from('新版'), basis.subarray(100)]);
    const basisPath = join(folder, 'basis.bin');
    await writeFile(basisPath, basis);
    const signature = await signFile(basisPath, 64);
    const delta = await createDelta(signature, target);

    const renamed = { ...delta, target: { ...delta.target, sha256: digest(Buffer.from('别的版本')) } };
    await assert.rejects(receiveDelta({ basisPath, delta: renamed,
      outputPath: join(folder, 'a.bin') }), /摘要/);

    const corrupted = deltaFromJSON(deltaToJSON(delta));
    const literal = corrupted.ops.find(op => op.op === 'literal');
    assert.ok(literal, '应存在字面量操作');
    literal.data[0] ^= 0xff;
    await assert.rejects(receiveDelta({ basisPath, delta: corrupted,
      outputPath: join(folder, 'b.bin') }), /摘要/);

    const outOfRange = { ...delta, ops: [{ op: 'copy', index: 10_000 }] };
    await assert.rejects(receiveDelta({ basisPath, delta: outOfRange,
      outputPath: join(folder, 'c.bin') }), /越界/);

    assert.deepEqual(await readdir(folder), ['basis.bin']);
  });
});

test('输出与基底同路径时，整份校验完成后才覆盖', async () => {
  await withTemp(async folder => {
    const basis = syntheticBytes(41, 2048);
    const target = Buffer.concat([Buffer.from('就地更新:'), basis.subarray(0, 1000),
      syntheticBytes(43, 50), basis.subarray(1000)]);
    const basisPath = join(folder, 'basis.bin');
    await writeFile(basisPath, basis);
    const signature = await signFile(basisPath, 64);
    const delta = await createDelta(signature, target);
    const result = await receiveDelta({ basisPath, delta, outputPath: basisPath });
    assert.equal(result.sha256, digest(target));
    assert.deepEqual(await readFile(basisPath), target);

    const basisAfter = syntheticBytes(47, 2048);
    await writeFile(basisPath, basisAfter);
    const broken = deltaFromJSON(deltaToJSON(await createDelta(await signFile(basisPath, 64), target)));
    broken.target = { ...broken.target, sha256: digest(Buffer.from('伪造')) };
    await assert.rejects(receiveDelta({ basisPath, delta: broken, outputPath: basisPath }), /摘要/);
    assert.deepEqual(await readFile(basisPath), basisAfter, '失败时基底不得被覆盖');
  });
});

test('字面量缓冲受控：超限即分段冲刷且重建不变', async () => {
  const basis = syntheticBytes(53, 512);
  const target = syntheticBytes(59, 5000);
  const signature = createSignature(basis, 64);
  const ops = await collect(matchOps(signature, target, { literalLimit: 100 }));
  const literals = ops.filter(op => op.op === 'literal');
  assert.ok(literals.length > 40, `应分段冲刷，实际 ${literals.length} 段`);
  assert.ok(literals.every(op => op.data.length <= 100));
  const total = literals.reduce((sum, op) => sum + op.data.length, 0);
  assert.equal(total, target.length);
});

test('目标来源可为异步流，空目标与空基底行为正确', async () => {
  await withTemp(async folder => {
    const basis = syntheticBytes(61, 300);
    async function* stream() {
      yield basis.subarray(0, 100);
      yield basis.subarray(100, 250);
      yield basis.subarray(250);
    }
    const signature = createSignature(basis, 64);
    const ops = await collect(matchOps(signature, stream()));
    assert.ok(ops.every(op => op.op === 'copy'));

    const emptySignature = createSignature(Buffer.alloc(0), 64);
    assert.equal(emptySignature.blocks.length, 0);
    const delta = await createDelta(emptySignature, Buffer.from('全新内容'));
    assert.ok(delta.ops.every(op => op.op === 'literal'));
    const basisPath = join(folder, 'empty.bin');
    const outputPath = join(folder, 'output.bin');
    await writeFile(basisPath, Buffer.alloc(0));
    await receiveDelta({ basisPath, delta, outputPath });
    assert.deepEqual(await readFile(outputPath), Buffer.from('全新内容'));
  });
});

test('随机编辑序列下差量往返逐字节一致', async () => {
  await withTemp(async folder => {
    for (const seed of [71, 73, 79]) {
      const basis = syntheticBytes(seed, 8192);
      let target = basis;
      for (let i = 0; i < 12; i += 1) {
        const dice = syntheticBytes(seed * 1000 + i, 4);
        const at = dice[0] * 256 + dice[1];
        const span = 1 + dice[2] % 200;
        const inject = syntheticBytes(seed * 7000 + i, 1 + dice[3] % 120);
        const cut = Math.min(at, target.length);
        target = Buffer.concat([target.subarray(0, cut), inject,
          target.subarray(Math.min(cut + span, target.length))]);
      }
      const basisPath = join(folder, `basis-${seed}.bin`);
      const outputPath = join(folder, `output-${seed}.bin`);
      await writeFile(basisPath, basis);
      const signature = await signFile(basisPath, 64);
      const delta = await createDelta(signature, target);
      const result = await receiveDelta({ basisPath, delta, outputPath });
      assert.equal(result.sha256, digest(target));
      assert.deepEqual(await readFile(outputPath), target);
      assert.ok(result.copyBlocks > 0, '随机编辑后仍应命中基底块');
    }
  });
});

test('协议常量与提交的协议登记一致', async () => {
  const registered = JSON.parse(await readFile(join(fixtures, 'protocol.json'), 'utf8'));
  assert.equal(registered.version, PROTOCOL.version);
  assert.equal(registered.weak, PROTOCOL.weak);
  assert.equal(registered.strong, PROTOCOL.strong);
  assert.deepEqual(registered.operations, PROTOCOL.operations);
  assert.ok(registered.blockSizes.includes(DEFAULT_BLOCK_SIZE));
});

test('演练覆盖各场景且实际传输量小于整份复制', async () => {
  const report = await drill();
  const byName = Object.fromEntries(report.scenarios.map(s => [s.name, s]));
  for (const name of ['头部插入', '重复段', '弱校验碰撞']) {
    const scenario = byName[name];
    assert.ok(scenario, `缺少场景 ${name}`);
    assert.equal(scenario.verified, true, `${name} 必须重建核验通过`);
  }
  for (const name of ['头部插入', '重复段']) {
    const scenario = byName[name];
    assert.ok(scenario.deltaBytes < scenario.targetSize,
      `${name} 差量 ${scenario.deltaBytes} 应小于整份 ${scenario.targetSize}`);
  }
  assert.ok(byName['头部插入'].copyBlocks > 10);
  assert.ok(byName['重复段'].copyBlocks > 5);
  assert.ok(byName['弱校验碰撞'].literalBytes >= 64);
  const tamper = byName['故意改动基底'];
  assert.equal(tamper.rejected, true);
  assert.match(tamper.rejection, /不可信/);
  assert.equal(tamper.outputAbsent, true);
  assert.equal(tamper.failedBasisRejected, true);
  assert.match(tamper.failedBasisRejection, /身份不符/);
  assert.equal(tamper.verified, true);
});
