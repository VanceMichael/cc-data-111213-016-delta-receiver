import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { inspect, sample } from '../src/domain.js';
import { fixedBlocks } from '../src/domain.js';

test('既有资料查看与本地来源符合领域约定', async () => {
  const result = await inspect(sample);
  assert.ok(result.blocks.length > 60);
  assert.equal(fixedBlocks(Buffer.from('12345'), 3)[1].length, 2);
  assert.throws(() => fixedBlocks(Buffer.alloc(1), 0), /无效/);
});
