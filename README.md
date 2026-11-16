# 远端大文件的滚动签名差量领取

delta-receiver 用于合作资料的本地查看和来源保存。当前版本支持人工触发的整份资料查看与字节级归档，资料对象按内容摘要保存，每次领取保留单独回执。自动组织领域资料的能力与人工查看入口分别演进。

针对合作方每次只修改成果文件中的一小段、却反复传输整份几百兆资料的问题，本版本新增 rsync 风格的差量领取：本地先就旧文件生成滚动签名，由本地模拟的远端按签名给出匹配块引用与字面量，接收方流式重建并在整份校验通过后原子接纳。这里不兼容系统 rsync 命令，也不启动远端 shell。

## 运行环境

使用 Node.js 22。依赖已锁定；首次准备执行 `npm ci --ignore-scripts`，正式运行无需下载资料或软件。全部样例使用合成数据与本机来源，不连接生产系统。

```bash
npm run check
npm test
npm run demo
npm run drill
```

`npm run demo` 在临时目录实际读取资料、归档并重新核验摘要，退出时清理临时内容。`npm run drill` 演练差量领取：逐个场景比较实际传输量（签名 + 差量）与整份复制，覆盖头部插入、重复段、弱校验碰撞与故意改动基底后的拒绝与重试。浏览器项目还会启动本地门户和 Chromium 并完成可见页面查看；浏览器在环境准备阶段安装，正式运行不下载。正常演示应在九十秒内结束。

## 资料操作

```bash
npm start -- inspect fixtures/base.bin
npm start -- capture fixtures/base.bin .local/archive
npm start -- list .local/archive
```

`capture` 只表示来源字节已保存，不声称领域流程已自动完成。已有查看功能只展示现有资料，不替代业务接纳判断。`scripts/create-fixtures.js` 用于维护者重建合成资料；运行与测试直接读取已提交的资料。

## 差量领取

```bash
npm start -- sign fixtures/base.bin 64                 # 由本地基底生成滚动签名
npm start -- delta fixtures/base.bin fixtures/new.bin  # 模拟远端按签名产出差量
npm start -- receive fixtures/base.bin fixtures/new.bin updated.bin .local/archive
npm start -- drill                                     # 演练并比较实际传输量
```

协议登记在 `fixtures/protocol.json`，实现常量见 `src/delta.js`：

- **签名**（领取方 → 来源方）：`blockSize`、弱校验 `adler32`、强摘要 `sha256`，逐块记录 `{weak, strong, length}`，并登记基底身份 `{sha256, size}`。
- **差量**（来源方 → 领取方）：头部回登记基底身份并给出新文件摘要 `{sha256, size}`；操作序列只有两种——`copy` 引用基底第 N 块，`literal` 携带字面量字节（线格式为 base64）。
- **滚动匹配**：弱校验以 O(1) 滑动更新，逐字节探测任意偏移；弱校验命中后必须再比长度与强摘要才采纳。因此头部插入一个字节后仍能命中后续块，重复块取首个匹配索引，尾部短块按实际长度参与，弱校验碰撞只会退化为字面量，不会重建出错误内容。
- **流式重建与原子接纳**：操作逐条写入输出同目录的临时文件，内存只占块缓冲与定长字面量缓冲；整份摘要等于头部登记的新文件摘要、且基底在领取期间未被替换（打开句柄复核摘要 + 路径状态比对），才原子改名覆盖输出，随后按内容摘要纳入归档并登记回执。

安全约定：

- 领取前核对本地基底与签名身份，不符即拒绝使用其块引用；领取中基底被替换（原位改写或改名替换）则已收到的引用不再可信，本次拒绝并清除临时残件。
- 远端版本变化或差量被篡改都会使整份摘要不符，不能继续拼接接纳。
- 失败的领取不会留下可用残件，重试必须重新核对基底身份，失败文件不能作为下一次的可信基底。

## 目录约定

- `src/domain.js`：现有领域读取和查看接口。
- `src/archive.js`：内容对象、来源回执与完整性检查。
- `src/delta.js`：滚动签名、差量匹配、流式重建与原子接纳。
- `src/drill.js`：差量领取演练场景与传输量对比。
- `fixtures/`：本地资料与领域配置。
- `test/`：已有行为的运行验证，使用独立临时目录。

## Linux 环境

`Dockerfile` 使用 Node.js 22 镜像；浏览器项目使用包含 Chromium 的运行镜像。可执行 `docker build -t delta-receiver:local .` 后运行 `docker run --rm --network none delta-receiver:local npm test`。测试中的 HTTP、MQTT 和门户都仅绑定回环地址；不需要第二个容器。构建阶段准备依赖，运行时不安装依赖。
