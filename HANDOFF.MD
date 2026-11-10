# 已验证的排障记录

## Linux TSan：使用匹配的 SaltsBase SDK（2026-11-10）

- 触发：PR #280 的 CI 42721872933 在 M6 并发 mTLS 中报告两个 worker
  对共享池回收地址的 memcpy / mem_set_used 竞争；恢复与过期证书测试已通过。
- 事实：按发布清单校验的 SaltsBase v0.1.1 普通 Release 运行库不导入
  `__tsan_*`；buffer 回收内部使用 acquire/release 原子操作，未插桩时
  检测器无法观察这些同步事件。缺失插桩是待验证解释，不能据此忽略报告。
- SaltsBase PR #3 合并为 `c8efb731`，完整十配置 CI 42726334488 通过。
  新增既有 Linux TSan preset 的 CI 包装与 SDK 产物，修复媒体测试迁移后
  的依赖、旧 API 名称和相邻 PCM fixture 路径；正式 buffer 测试增加
  16 worker 共享池与 retained slice 回归。没有修改 TinyTest 或生产实现。
- 生产者 TSan 完整图构建后，169/169 CTest 通过（52.36 秒），随后安装并
  上传 artifact 13722652163；TAR SHA-256 为
  `67d3c1cc11704716397176637badb74bec06e649c93361d80fb60cb963b4cf29`。
  该运行库包含 TSan 原子、读写插桩导入。
- 临时分支仅选择既有 Linux TSan lane 并替换 SDK 输入；Core 生产及测试
  源码保持 PR #280 的 `96daa7e`。CI 42727211874 通过完整构建和
  `ctest --preset llvm-native-tsan-user`：104/104，372.09 秒。
  M6 并发 mTLS 通过（1.25 秒），标准/ShangMi 恢复通过（27.78/0.52 秒）。
  初次对照 42726985795 在 configure 前因下载目录布局失败，修正明确的
  artifact 解压布局后才得到上述结果；原失败保留，不视为已执行测试。
- 推论与限制：本次未出现池报告，支持同步可见性解释，但一次通过不排除
  间歇性生命周期缺陷；旧 GmSSL ctime 竞争及 #276 原始问题仍未归因。
  第三方预编译依赖仍保留原插桩状态。不能把匹配 SDK 等同于全部依赖无竞争。
- 临时 workflow 已恢复，临时本地及远端分支已删除；日志、摘要和临时 patch
  存于本地 `build/issue219-evidence/`，不提交验证分支或依赖二进制。
- 长期配置让 TSan lane 必需消费 `linux-clang-x64-tsan`。原 v0.1.1 发布
  清单不含此 SDK；须先发布具有此条目的新版本，再推送并验证消费方配置。
  缺少 SDK 时沿用现有 prepare 的明确失败，不退回普通 Release SDK。

## MSVC Release：TLS 测试栈溢出与 owner 审计（2026-11-09）

- 触发：CI 42643612615 中 `saltscore.gmssl_tls_io_abi` 报 SEGFAULT，
  `saltscore.cnet_native_crypto_owner` 报 `COFF symbol reader required`。
- TLS 原因：本机 MSVC Release 同样失败；LLDB 捕获 `0xc00000fd`。
  对象反汇编显示 local sending-key suite 的栈帧为 1,449,712 字节，
  peer-spacing suite 为 2,490,224 字节，多份大型 TLS 连接累积在同一栈帧。
  改用 suite 拥有的串行静态 fixture；既有 prepare 函数逐次完整重置。
  不需要扩大线程栈，也不修改 TinyTest 或发布的 SaltsBase SDK。
- 工具查找原因：MSVC 没有 `CMAKE_NM`，提前将查找结果变量设为空字符串会
  阻止 `find_program` 搜索。仅在非 MSVC 分支赋值；MSVC 从配置的 linker
  目录必需查找 dumpbin/LLVM 工具，不增加 PATH 备用来源。
- 实际审计随后发现：MSVC `/OPT:REF` 会裁剪未使用的 session 级指纹函数
  `tls_get_peer_certificate_sha256`。CNet 使用 stream facade 自行计算指纹。
  静态库仍必须包含该函数的唯一 GmSSL 实现；链接保留它时也必须验证其归属。
  正式 Python 回归覆盖裁剪、缺失的库定义、错误归属及重复运行时定义。
- 验证：使用原始 SaltsBase v0.1.1 与 vcpkg-cache v0.1.2 SDK，
  `msvc-release-user` 和 `native-release-user` 均构建并通过 TLS ABI CTest
  （526 用例、28632 断言），以及 owner 审计和 15 项 Python 审计回归。
  通过 user preset 的 CTest `--tests-from-file` 选择上述正式测试；该文件路径
  使用绝对路径，避免 CTest 切换到 build 目录后无法读取相对路径。
- 独立残余问题：同次 CI 的 M6 并发 mTLS TSan 失败包含 GmSSL
  `x509_validity_print` 的 `ctime` 共享存储竞争，保留失败记录；上述两个 MSVC
  修复不证明该依赖诊断路径已修复。
