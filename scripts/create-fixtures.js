import { mkdir as ensureFixtureDirectory } from 'node:fs/promises';
await ensureFixtureDirectory('fixtures', {recursive:true});

import { writeFile } from 'node:fs/promises';
const base = Buffer.from('ABCDE0123456789AB'.repeat(64) + '尾部');
await writeFile('fixtures/base.bin', base);
await writeFile('fixtures/new.bin', Buffer.concat([Buffer.from('x'), base.subarray(0, 512), Buffer.from('变动'), base.subarray(516)]));
await writeFile('fixtures/protocol.json', JSON.stringify({ version: 1, weak: 'adler32', strong: 'sha256',
 operations: ['copy', 'literal'], blockSizes: [8, 16, 64],
 identity: { basis: 'sha256', target: 'sha256' },
 acceptance: '整份摘要核验通过且基底未变后，原子改名接纳；失败残件不得作为后续基底' }, null, 2));
