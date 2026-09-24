# 本地诊断工具

这些工具供开发者定位微信内部结构，不参与插件编译，也不会随微信自动运行。
下面的表情工具从仓库根目录使用；新增的 `.lldb` 文件只注册命令，不扫描进程、
不自动继续运行，也不带任何实际表情的 MD5、密文样本或密钥。

## 工具用途

| 工具 | 用途 | 输出 |
| --- | --- | --- |
| `arm64_xrefs.py` | 在本地核心库中查找 ARM64 地址引用或直接调用 | 文件内的代码偏移 |
| `qt_sticker_runtime_probe.py` | 检查聊天行、表情 XML 所在位置及界面对象关系 | 类名、字段偏移、数量和判断结果，不输出正文、MD5、URL 或密钥 |
| `qt_emoticon_meta_probe.py` | 查找 Qt 表情服务的元对象、方法和实例 | 类名、方法名、代码偏移及对象地址 |
| `emoticon_md5_probe.py` | 根据手动输入的 MD5 查找附近的表情元数据 | MD5、十六进制候选值、腾讯资源 URL；可能包含密钥或带凭据的地址 |
| `emoticon_image_key_probe.py` | 为旧本地图片缓存尝试 AES-128-ECB 候选密钥 | 候选密钥和解密后的文件头；命中仍需进一步验证 |
| `emoticon_open_trace.py` | 跟踪 `Emoticon` 缓存文件被读取时的调用栈 | 命中次数、微信核心库内偏移，不输出文件路径 |

`emoticon_image_key_probe.py` 是独立的缓存格式研究工具，不是当前表情导出功能的
AES 下载解密实现。两个元数据/密钥探针的实机输出只留在本地，不要作为测试数据提交。

Qt 表情探针仅支持微信 **4.1.13 build 269631 arm64**，核心库 UUID 为
`918FFBFD-E18D-363F-B07C-B8D7F1436727`；命令会在 UUID 不匹配时退出。
文件读取跟踪使用 ARM64 寄存器约定。其他已有的 `qt_*.lldb` 是历史调试脚本，
部分含旧会话的对象地址，不适合作为通用入口。

## 检查当前聊天中的表情

先在微信中打开目标聊天。使用已允许 LLDB 调试的本机微信，在仓库根目录执行：

```bash
lldb -n WeChat
```

附加后微信会暂停，在 LLDB 中逐行执行：

```text
expression -l objective-c++ -- @import AppKit
expression -l objective-c++ -- @import ObjectiveC
command source tools/qt_sticker_runtime_probe.lldb
sticker-runtime-probe
process detach
quit
```

`process detach` 让微信继续运行并退出调试连接。命令报错时也执行它。
这些探针只用于诊断；菜单出现及保存成功仍须通过微信界面验证。

## 查询 Qt 表情服务

附加到微信后执行；可以用类名参数覆盖默认的 `mmui::EmoticonDataStore`：

```text
command source tools/qt_emoticon_meta_probe.lldb
emoticon-meta-probe
emoticon-meta-probe mmui::EmoticonDataStore
process detach
```

## 按样本查询元数据或候选密钥

加载脚本后显式传入自己的参数。下面的尖括号表示占位符，不是可直接执行的样本。

```text
command source tools/emoticon_md5_probe.lldb
emoticon-md5-probe <表情的32位十六进制MD5>
process detach
```

```text
command source tools/emoticon_image_key_probe.lldb
emoticon-image-key-probe <16字节密文块对应的32位十六进制字符串>
process detach
```

两个命令都扫描进程的可读数据区域，微信会在扫描期间保持暂停。

## 跟踪缓存文件读取

```text
command source tools/emoticon_open_trace.lldb
emoticon-open-trace
process continue
```

随后在微信中打开目标表情。完成后回到 LLDB 按 `Ctrl+C`，再执行
`process detach`，解除本次会话的断点和调试连接。

## 离线查找机器码引用

这个工具只读取本地二进制，不附加微信。先准备 ARM64 单架构核心库，例如：

```bash
lipo /Applications/WeChat.app/Contents/Resources/wechat.dylib \
  -thin arm64 -output /tmp/wechat-arm64.dylib
python3 tools/arm64_xrefs.py /tmp/wechat-arm64.dylib 0x5570764 --branches
python3 tools/arm64_xrefs.py /tmp/wechat-arm64.dylib 0x98a5da0 --target-page
python3 tools/arm64_xrefs.py --help
```

默认扫描范围对应上述微信版本；其他范围通过 `--text-start` 和 `--text-end`
显式指定，起止位置必须按 4 字节对齐且位于文件内。目标使用不含 ASLR 的代码或
数据地址。工具采用文件偏移作为指令地址，适用于该核心库的地址布局，不会自动解析
任意 Mach-O 的虚拟地址映射。ADRP 查找是附近指令的启发式匹配，结果需用反汇编核对。

Python 的 `__pycache__`、`.pyc`、`.pyo` 已加入忽略规则，可以随时删除。
