import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Archive } from './archive.js';
import { signFile, createDelta, receiveDelta, transferredBytes, DEFAULT_BLOCK_SIZE } from './delta.js';

const fixtures = fileURLToPath(new URL('../fixtures/', import.meta.url));

// 确定性合成字节，避免演练依赖外部数据。
export function syntheticBytes(seed, length) {
  const out = Buffer.allocUnsafe(length);
  let state = seed >>> 0;
  for (let i = 0; i < length; i += 1) {
    state = (state * 1664525 + 1013904223) >>> 0;
    out[i] = state >>> 24;
  }
  return out;
}

// 两个 64 字节块：字节不同但 adler32 弱校验相同（a 与 b 同余 65521），
// 用于演练弱校验碰撞不能使重建出错。
export function collisionPair() {
  const first = Buffer.alloc(64);
  first[33] = 149;
  first[60] = 255; first[61] = 255; first[62] = 255; first[63] = 255;
  const second = Buffer.from(first);
  second[0] = 255; second[1] = 255; second[2] = 255; second[3] = 255; second[4] = 149;
  second[33] = 0;
  second[60] = 0; second[61] = 0; second[62] = 0; second[63] = 0;
  return [first, second];
}

async function roundTrip(directory, { basis, target, blockSize = DEFAULT_BLOCK_SIZE, withArchive = false }) {
  await mkdir(directory, { recursive: true });
  const basisPath = join(directory, 'basis.bin');
  const targetPath = join(directory, 'target.bin');
  const outputPath = join(directory, 'output.bin');
  await writeFile(basisPath, basis);
  await writeFile(targetPath, target);
  const signature = await signFile(basisPath, blockSize);
  const delta = await createDelta(signature, targetPath);
  const archive = withArchive ? new Archive(join(directory, 'archive')) : null;
  const received = await receiveDelta({ basisPath, delta, outputPath,
    archive, metadata: { source: targetPath } });
  const output = await readFile(outputPath);
  return { signature, delta, received, verified: output.equals(target), archive };
}

function entry(name, blockSize, basis, target, { signature, delta, received, verified }) {
  return { name, blockSize,
    basisSize: basis.length, targetSize: target.length,
    signatureBytes: Buffer.byteLength(JSON.stringify(signature)),
    deltaBytes: transferredBytes(delta),
    literalBytes: received.literalBytes, copyBlocks: received.copyBlocks, verified };
}

// 演练：对每个场景比较实际传输量（签名 + 差量）与整份复制，
// 并覆盖头部插入、重复段、弱校验碰撞与故意改动基底。
export async function drill() {
  const root = await mkdtemp(join(tmpdir(), 'delta-drill-'));
  try {
    const scenarios = [];

    const base = await readFile(join(fixtures, 'base.bin'));
    const updated = await readFile(join(fixtures, 'new.bin'));
    const head = await roundTrip(join(root, 'head-insert'),
      { basis: base, target: updated, withArchive: true });
    scenarios.push({ ...entry('头部插入', DEFAULT_BLOCK_SIZE, base, updated, head),
      receipt: head.received.receipt?.id ?? null,
      receipts: (await head.archive.receipts()).length });

    const segment = syntheticBytes(7, 64);
    const altered = Buffer.from(segment);
    altered[63] ^= 0xff;
    const repeatedBasis = Buffer.concat([...Array(6).fill(segment), Buffer.from('—— 分隔 ——'), ...Array(6).fill(segment)]);
    const repeatedTarget = Buffer.concat([...Array(5).fill(segment), altered, ...Array(6).fill(segment), Buffer.from('新尾')]);
    scenarios.push(entry('重复段', DEFAULT_BLOCK_SIZE, repeatedBasis, repeatedTarget,
      await roundTrip(join(root, 'repeated'), { basis: repeatedBasis, target: repeatedTarget })));

    const [alien, resident] = collisionPair();
    const fillerA = syntheticBytes(11, 64);
    const fillerB = syntheticBytes(13, 64);
    const collisionBasis = Buffer.concat([resident, fillerA, fillerB]);
    const collisionTarget = Buffer.concat([Buffer.from('前缀:'), alien, resident]);
    scenarios.push(entry('弱校验碰撞', DEFAULT_BLOCK_SIZE, collisionBasis, collisionTarget,
      await roundTrip(join(root, 'collision'), { basis: collisionBasis, target: collisionTarget })));

    scenarios.push(await tamperScenario(join(root, 'tamper')));

    return { generatedAt: new Date().toISOString(), scenarios };
  } finally { await rm(root, { recursive: true, force: true }); }
}

// 故意在领取途中改动基底：本次必须拒绝且不留残件；
// 失败文件不能作为下一次的可信基底；恢复基底后重试必须成功。
async function tamperScenario(directory) {
  await mkdir(directory, { recursive: true });
  const basis = syntheticBytes(29, 4096);
  const target = Buffer.concat([Buffer.from('头'), basis.subarray(0, 2048),
    Buffer.from('—— 中段改动 ——'), basis.subarray(2048)]);
  const basisPath = join(directory, 'basis.bin');
  const targetPath = join(directory, 'target.bin');
  const outputPath = join(directory, 'output.bin');
  await writeFile(basisPath, basis);
  await writeFile(targetPath, target);
  const signature = await signFile(basisPath, DEFAULT_BLOCK_SIZE);
  const delta = await createDelta(signature, targetPath);

  const corrupted = syntheticBytes(31, 4096);
  let tampered = false;
  const onOperation = async (op, { written }) => {
    if (!tampered && written >= delta.target.size) {
      tampered = true;
      await writeFile(basisPath, corrupted);
    }
  };
  let rejection = null;
  try {
    await receiveDelta({ basisPath, delta, outputPath, onOperation });
  } catch (error) { rejection = error.message; }
  const outputAbsent = await readFile(outputPath).then(() => false, () => true);

  let failedBasisRejection = null;
  try {
    await receiveDelta({ basisPath, delta, outputPath: join(directory, 'misguided.bin') });
  } catch (error) { failedBasisRejection = error.message; }

  await writeFile(basisPath, basis);
  const retry = await receiveDelta({ basisPath, delta, outputPath });
  const verified = (await readFile(outputPath)).equals(target);

  return { name: '故意改动基底', basisSize: basis.length, targetSize: target.length,
    deltaBytes: transferredBytes(delta),
    rejected: rejection !== null, rejection,
    outputAbsent,
    failedBasisRejected: failedBasisRejection !== null, failedBasisRejection,
    retried: true, verified,
    retryTransferred: retry.transferredBytes };
}
