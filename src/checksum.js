// Adler-32 弱校验：可按字节滚动，配合强摘要（sha256）使用。
// 弱校验只负责快速筛除不匹配窗口；任何弱碰撞都必须由强摘要拦截。
export const ADLER_MOD = 65521;

export function adler32(bytes) {
  let a = 1;
  let b = 0;
  for (let i = 0; i < bytes.length; i++) {
    a = (a + bytes[i]) % ADLER_MOD;
    b = (b + a) % ADLER_MOD;
  }
  return packWeak(a, b);
}

// 窗口滑出 outByte、滑入 inByte 时的 O(1) 滚动更新。
export function rollAdler32(state, outByte, inByte, blockSize) {
  let a = (state.a - outByte + inByte) % ADLER_MOD;
  if (a < 0) a += ADLER_MOD;
  let b = (state.b - (blockSize * outByte) % ADLER_MOD + a - 1) % ADLER_MOD;
  if (b < 0) b += ADLER_MOD;
  return { a, b };
}

export function packWeak(a, b) {
  return (((b << 16) >>> 0) | a) >>> 0;
}

export function unpackWeak(weak) {
  return { a: weak & 0xffff, b: (weak >>> 16) & 0xffff };
}
