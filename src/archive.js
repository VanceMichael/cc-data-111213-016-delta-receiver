import { createReadStream } from 'node:fs';
import { copyFile, mkdir, open, readFile, rename, readdir, rm } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';

export function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export async function hashFile(path) {
  const hash = createHash('sha256');
  let size = 0;
  for await (const chunk of createReadStream(path)) { hash.update(chunk); size += chunk.length; }
  return { sha256: hash.digest('hex'), size };
}

export class Archive {
  constructor(directory) { this.directory = resolve(directory); }
  async initialize() {
    await mkdir(join(this.directory, 'objects'), { recursive: true });
    await mkdir(join(this.directory, 'receipts'), { recursive: true });
  }
  async writeAtomic(path, bytes) {
    const temporary = `${path}.${randomUUID()}.tmp`;
    const handle = await open(temporary, 'wx', 0o600);
    try { await handle.writeFile(bytes); await handle.sync(); }
    finally { await handle.close(); }
    try { await rename(temporary, path); }
    finally { await rm(temporary, { force: true }); }
  }
  async accept(bytes, metadata) {
    await this.initialize();
    const sha256 = digest(bytes);
    await this.writeAtomic(join(this.directory, 'objects', sha256), bytes);
    const receipt = { id: randomUUID(), sha256, size: bytes.length,
      observedAt: new Date().toISOString(), metadata };
    await this.writeAtomic(join(this.directory, 'receipts', `${receipt.id}.json`),
      JSON.stringify(receipt, null, 2));
    return receipt;
  }
  async acceptFile(path, metadata = {}, { expectedSha256 } = {}) {
    await this.initialize();
    const { sha256, size } = await hashFile(path);
    if (expectedSha256 && sha256 !== expectedSha256) throw new Error('对象完整性校验失败');
    const temporary = join(this.directory, 'objects', `${sha256}.${randomUUID()}.tmp`);
    await copyFile(path, temporary);
    const handle = await open(temporary, 'r');
    try { await handle.sync(); }
    finally { await handle.close(); }
    try { await rename(temporary, join(this.directory, 'objects', sha256)); }
    finally { await rm(temporary, { force: true }); }
    const receipt = { id: randomUUID(), sha256, size,
      observedAt: new Date().toISOString(), metadata };
    await this.writeAtomic(join(this.directory, 'receipts', `${receipt.id}.json`),
      JSON.stringify(receipt, null, 2));
    return receipt;
  }
  async receipts() {
    await this.initialize();
    const files = (await readdir(join(this.directory, 'receipts')))
      .filter(name => name.endsWith('.json')).sort();
    return Promise.all(files.map(name => readFile(join(this.directory, 'receipts', name), 'utf8').then(JSON.parse)));
  }
  async read(sha256) {
    if (!/^[a-f0-9]{64}$/.test(sha256)) throw new Error('对象摘要格式不正确');
    const bytes = await readFile(join(this.directory, 'objects', sha256));
    if (digest(bytes) !== sha256) throw new Error('对象完整性校验失败');
    return bytes;
  }
}
