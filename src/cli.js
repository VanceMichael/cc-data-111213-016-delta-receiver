import { readFile, writeFile, mkdtemp, rm, open } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, basename } from 'node:path';
import { Archive } from './archive.js';
import { inspect, sample, sign, loadSignature, deltaFrames, deltaProtocol } from './domain.js';
import { createDelta, DeltaError } from './delta.js';

const [command = 'help', ...args] = process.argv.slice(2);

async function writeFrames(path, frames) {
  const handle = await open(path, 'w', 0o600);
  let wireBytes = 0;
  try {
    for await (const frame of frames) { await handle.writeFile(frame); wireBytes += frame.length; }
  } finally { await handle.close(); }
  return wireBytes;
}

async function readFrames(path) {
  const handle = await open(path, 'r');
  try {
    const queue = [];
    const size = (await handle.stat()).size;
    let offset = 0;
    while (offset < size) {
      const head = Buffer.alloc(5);
      await handle.read(head, 0, 5, offset);
      const length = head.readUInt32BE(1);
      const frame = Buffer.alloc(9 + length);
      head.copy(frame, 0);
      await handle.read(frame, 5, length + 4, offset + 5);
      queue.push(frame);
      offset += 9 + length;
    }
    return queue;
  } finally { await handle.close(); }
}

async function run() {
  if (command === 'help') {
    console.log(JSON.stringify({
      usage: 'npm start -- <命令> [参数...]',
      commands: ['inspect', 'capture', 'list', 'sign', 'delta', 'apply-delta', 'demo'],
      deltaProtocol,
    }, null, 2));
  } else if (command === 'inspect') {
    const [file] = args;
    if (!file) throw new Error('需要资料路径');
    console.log(JSON.stringify(await inspect(resolve(file)), null, 2));
  } else if (command === 'capture') {
    const [file, directory = '.local/archive'] = args;
    if (!file) throw new Error('需要资料路径');
    const inventory = await inspect(resolve(file));
    const receipt = await new Archive(directory).accept(await readFile(file),
      { source: resolve(file), inventory });
    console.log(JSON.stringify(receipt, null, 2));
  } else if (command === 'list') {
    const [directory = '.local/archive'] = args;
    console.log(JSON.stringify(await new Archive(directory).receipts(), null, 2));
  } else if (command === 'sign') {
    const [basePath, signaturePath] = args;
    if (!basePath) throw new Error('用法：sign <基底文件> [签名输出路径]');
    const { signature, wire } = await sign(resolve(basePath));
    const out = resolve(signaturePath ?? `${basename(basePath)}.sig`);
    await writeFile(out, wire, { mode: 0o600 });
    console.log(JSON.stringify({
      signature: out, baseSha256: signature.baseSha256, baseSize: signature.baseSize,
      blockSize: signature.blockSize, blockCount: signature.blockCount, signatureBytes: wire.length,
    }, null, 2));
  } else if (command === 'delta') {
    const [basePath, targetPath, deltaPath, signaturePath] = args;
    if (!basePath || !targetPath) throw new Error('用法：delta <基底文件> <新文件> [差量输出路径] [签名输出路径]');
    const { signature, wire } = await sign(resolve(basePath));
    const sigOut = resolve(signaturePath ?? `${basename(basePath)}.sig`);
    await writeFile(sigOut, wire, { mode: 0o600 });
    const out = resolve(deltaPath ?? `${basename(targetPath)}.delta`);
    const wireBytes = await writeFrames(out, deltaFrames(signature, resolve(targetPath)));
    const fullSize = (await inspect(resolve(targetPath))).size;
    console.log(JSON.stringify({
      signature: sigOut, signatureBytes: wire.length,
      delta: out, deltaBytes: wireBytes,
      fullBytes: fullSize,
      transferredBytes: wire.length + wireBytes,
      savingPercent: Number((100 * (1 - (wire.length + wireBytes) / fullSize)).toFixed(2)),
    }, null, 2));
  } else if (command === 'apply-delta') {
    const [basePath, deltaPath, signaturePath, directory = '.local/archive'] = args;
    if (!basePath || !deltaPath || !signaturePath) {
      throw new Error('用法：apply-delta <基底文件> <差量文件> <签名文件> [归档目录]');
    }
    const signature = loadSignature(await readFile(resolve(signaturePath)));
    const frames = await readFrames(resolve(deltaPath));
    const archive = new Archive(directory);
    const receipt = await archive.acceptDelta(signature, frames, resolve(basePath),
      { source: resolve(deltaPath) });
    console.log(JSON.stringify(receipt, null, 2));
  } else if (command === 'demo') {
    console.log(JSON.stringify(await runDrill(), null, 2));
  } else {
    throw new Error('支持 inspect、capture、list、sign、delta、apply-delta、demo');
  }
}

// 差量演练：覆盖头部插入、重复段、弱碰撞、基底篡改、远端换版与失败重试。
async function runDrill() {
  const temporary = await mkdtemp(join(tmpdir(), 'delta-drill-'));
  try {
    // 既有整份流程保持可用
    const inventory = await inspect(resolve(sample));
    const archive = new Archive(join(temporary, 'archive'));
    const fullReceipt = await archive.accept(await readFile(sample), { source: sample, inventory });

    const unit = Buffer.from('测绘合作方-成果段落-0123456789'.repeat(8)); // 480 字节
    const base = Buffer.concat(Array.from({ length: 4096 }, () => unit)); // ~1.9 MiB
    const basePath = join(temporary, 'base.bin');
    await writeFile(basePath, base);

    const scenarios = [];
    // 1) 头部插入一个字节
    const inserted = Buffer.concat([Buffer.from('x'), base]);
    scenarios.push(await drillScenario(archive, temporary, basePath, base, '头部插入一字节', inserted));
    // 2) 中段小改动 + 重复段（内容本就高度重复）
    const edited = Buffer.concat([base.subarray(0, 700000), Buffer.from('###边界调整###'), base.subarray(700013)]);
    scenarios.push(await drillScenario(archive, temporary, basePath, base, '中段改动', edited));
    // 3) 弱校验碰撞：碰撞窗口必须走字面量且重建正确
    const collision = Buffer.concat([
      Buffer.from('ACAAAAAA'), Buffer.from('BABAAAAA'), base.subarray(16),
    ]);
    scenarios.push(await drillScenario(archive, temporary, basePath, base, '弱校验碰撞', collision));
    // 4) 故意改动基底：必须拒绝且不留暂存、不登记回执
    const tamper = await expectFailure(archive, basePath, inserted, '故意改动基底');
    scenarios.push(tamper);
    // 恢复被替换的基底，证明可信基底来自被核验的原文件而非失败暂存件
    await writeFile(basePath, base);
    // 4b) 远端版本在差量生成期间变化：必须以 REMOTE_CHANGED 中止
    const remotePath = join(temporary, 'remote.bin');
    await writeFile(remotePath, inserted);
    const remoteResult = await expectRemoteChange(basePath, remotePath);
    scenarios.push(remoteResult);
    // 5) 失败后恢复正确基底重试：失败文件不会成为可信基底
    const retry = await drillScenario(archive, temporary, basePath, base, '失败后重试', inserted);
    scenarios.push(retry);

    return {
      protocol: deltaProtocol,
      fullCopy: { bytes: fullReceipt.size, receipt: fullReceipt.id },
      scenarios,
      receipts: (await archive.receipts()).length,
    };
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

async function drillScenario(archive, temporary, basePath, base, name, target) {
  const targetPath = join(temporary, `target-${name}.bin`);
  await writeFile(targetPath, target);
  const { signature, wire: sigWire } = await sign(basePath);
  const frames = [];
  for await (const frame of deltaFrames(signature, targetPath)) frames.push(frame);
  const deltaBytes = frames.reduce((n, f) => n + f.length, 0);
  const receipt = await archive.acceptDelta(signature, frames, basePath, { scenario: name });
  const verified = (await archive.read(receipt.sha256)).equals(target);
  return {
    name,
    blockSize: signature.blockSize,
    blockCount: signature.blockCount,
    fullBytes: target.length,
    signatureBytes: sigWire.length,
    deltaBytes,
    transferredBytes: sigWire.length + deltaBytes,
    refs: receipt.transfer.refs,
    literalBytes: receipt.transfer.literalBytes,
    savingPercent: Number((100 * (1 - (sigWire.length + deltaBytes) / target.length)).toFixed(2)),
    verified,
  };
}

async function expectRemoteChange(basePath, remotePath) {
  const { signature } = await sign(basePath);
  try {
    const generation = (async () => {
      for await (const _frame of deltaFrames(signature, remotePath)) {
        // 头部产出后立刻模拟远端换版（长度变化）
        await writeFile(remotePath, Buffer.from('换版后的新内容'.repeat(200000)));
      }
    })();
    await generation;
    return { name: '远端生成期间换版', rejected: false };
  } catch (error) {
    return { name: '远端生成期间换版', rejected: true,
      code: error instanceof DeltaError ? error.code : error.name };
  }
}

async function expectFailure(archive, basePath, target, name) {
  const { signature } = await sign(basePath);
  const swapped = Buffer.from('Z'.repeat(signature.baseSize)); // 同大小、不同内容
  await writeFile(basePath, swapped);
  const frames = [];
  for await (const frame of createDelta(signature, target)) frames.push(frame);
  try {
    await archive.acceptDelta(signature, frames, basePath, { scenario: name });
    return { name, rejected: false };
  } catch (error) {
    return { name, rejected: true, code: error instanceof DeltaError ? error.code : error.name };
  }
}

run().catch(error => { console.error(error.message); process.exitCode = 1; });
