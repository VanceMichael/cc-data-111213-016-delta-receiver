import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Archive } from './archive.js';
import { inspect, sample } from './domain.js';
import { signFile, createDelta, receiveDelta, deltaToJSON, assertBlockSize, DEFAULT_BLOCK_SIZE } from './delta.js';
import { drill } from './drill.js';

const [command = 'help', ...rest] = process.argv.slice(2);
const commands = ['inspect', 'capture', 'list', 'sign', 'delta', 'receive', 'drill', 'demo'];

function blockSizeArgument(value) {
  if (value === undefined) return DEFAULT_BLOCK_SIZE;
  const parsed = Number(value);
  assertBlockSize(parsed);
  return parsed;
}

async function run() {
  if (command === 'help') {
    console.log(JSON.stringify({ usage: 'npm start -- <命令> [参数...]', commands,
      detail: {
        inspect: 'inspect <资料>',
        capture: 'capture <资料> [归档目录]',
        list: 'list [归档目录]',
        sign: 'sign <基底资料> [块大小]',
        delta: 'delta <基底> <新资料> [块大小]',
        receive: 'receive <基底> <新资料> <输出> [归档目录] [块大小]',
        drill: 'drill（演练差量领取并比较实际传输量）',
        demo: 'demo（整份归档演示）' } }, null, 2));
  } else if (command === 'inspect') {
    const [file] = rest;
    if (!file) throw new Error('需要资料路径');
    console.log(JSON.stringify(await inspect(resolve(file)), null, 2));
  } else if (command === 'capture') {
    const [file, directory = '.local/archive'] = rest;
    if (!file) throw new Error('需要资料路径');
    const inventory = await inspect(resolve(file));
    const receipt = await new Archive(directory).accept(await readFile(file),
      { source: resolve(file), inventory });
    console.log(JSON.stringify(receipt, null, 2));
  } else if (command === 'list') {
    const [directory = '.local/archive'] = rest;
    console.log(JSON.stringify(await new Archive(directory).receipts(), null, 2));
  } else if (command === 'sign') {
    const [file, blockSize] = rest;
    if (!file) throw new Error('需要基底资料路径');
    console.log(JSON.stringify(await signFile(resolve(file), blockSizeArgument(blockSize)), null, 2));
  } else if (command === 'delta') {
    const [basis, target, blockSize] = rest;
    if (!basis || !target) throw new Error('需要基底与新资料路径');
    const signature = await signFile(resolve(basis), blockSizeArgument(blockSize));
    const delta = await createDelta(signature, resolve(target));
    console.log(JSON.stringify(deltaToJSON(delta), null, 2));
  } else if (command === 'receive') {
    const [basis, target, output, directory = '.local/archive', blockSize] = rest;
    if (!basis || !target || !output) throw new Error('需要基底、新资料与输出路径');
    const signature = await signFile(resolve(basis), blockSizeArgument(blockSize));
    const delta = await createDelta(signature, resolve(target));
    const received = await receiveDelta({ basisPath: resolve(basis), delta,
      outputPath: resolve(output), archive: new Archive(directory),
      metadata: { source: resolve(target) } });
    console.log(JSON.stringify(received, null, 2));
  } else if (command === 'drill') {
    console.log(JSON.stringify(await drill(), null, 2));
  } else if (command === 'demo') {
    const temporary = await mkdtemp(join(tmpdir(), 'intake-'));
    try {
      const inventory = await inspect(resolve(sample));
      const archive = new Archive(temporary);
      const receipt = await archive.accept(await readFile(sample), { source: sample, inventory });
      console.log(JSON.stringify({ inventory, receipt, verified: (await archive.read(receipt.sha256)).length }, null, 2));
    } finally { await rm(temporary, { recursive: true, force: true }); }
  } else { throw new Error(`支持 ${commands.join('、')}`); }
}
run().catch(error => { console.error(error.message); process.exitCode = 1; });
