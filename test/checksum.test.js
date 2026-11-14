import test from 'node:test';
import assert from 'node:assert/strict';
import { adler32, rollAdler32, packWeak, ADLER_MOD } from '../src/checksum.js';

test('adler32 符合公开向量', () => {
  const vectors = [
    ['', 0x00000001],
    ['a', 0x00620062],
    ['abc', 0x024d0127],
    ['Wikipedia', 0x11e60398],
  ];
  for (const [text, expected] of vectors) {
    assert.equal(adler32(Buffer.from(text)), expected >>> 0);
  }
});

test('滚动更新与整块重算逐字节一致（覆盖不同块大小与内容）', () => {
  for (const blockSize of [8, 16, 64, 256, 1024]) {
    const stream = Buffer.alloc(blockSize * 4 + 3);
    for (let i = 0; i < stream.length; i++) stream[i] = (i * 31 + 7) % 251;
    // 初始窗口
    let state = { a: 1, b: 0 };
    for (let i = 0; i < blockSize; i++) {
      state.a = (state.a + stream[i]) % ADLER_MOD;
      state.b = (state.b + state.a) % ADLER_MOD;
    }
    for (let pos = 0; pos + blockSize < stream.length; pos++) {
      state = rollAdler32(state, stream[pos], stream[pos + blockSize], blockSize);
      const expect = adler32(stream.subarray(pos + 1, pos + 1 + blockSize));
      assert.equal(packWeak(state.a, state.b), expect,
        `块大小 ${blockSize} 位置 ${pos} 的滚动校验不一致`);
    }
  }
});

test('已知碰撞对弱校验相同但内容不同', () => {
  const a = Buffer.from('ACAAAAAA');
  const b = Buffer.from('BABAAAAA');
  assert.equal(adler32(a), adler32(b));
  assert.notEqual(a.toString(), b.toString());
});
