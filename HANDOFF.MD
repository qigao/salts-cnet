# 已验证的排障记录

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
