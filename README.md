# WeChatIntercept

macOS 微信防撤回工具，支持微信 4.1.x 系列，欢迎共建和 star。

---

## 功能

| 功能     | 说明                                                                     |
| -------- | ------------------------------------------------------------------------ |
| 防撤回   | 对方撤回的消息保留可见，自己撤回正常工作                                 |
| 气泡标记 | 原消息旁显示「已拦截撤回」，原文不变；目前仅适配 4.1.13 build 269631 arm64 核心库 |
| 撤回通知 | 弹出 macOS 系统通知，显示谁撤回了什么内容                                |
| 消息原文 | 通知中展示被撤回的原始消息（消息内容文本 / [图片] / [视频] / [文件] 等） |
| 自动适配 | 内置特征码搜索；微信更新后需重新运行安装脚本，无法匹配时安全失败         |

通知效果：

- `拦截到「张三」撤回了一条消息：你好`
- `拦截到「张三」撤回了一条消息：[图片]`
- 拿不到原文时降级：`拦截到「张三」撤回了一条消息`

---

## 快速开始

```bash
# 1. 安装防撤回（必须）
chmod +x patch.sh
./patch.sh
# 等价命令：./patch.sh --install

# 2. 安装消息监听（可选，撤回通知带原文）
./patch.sh --monitor-install
```

微信会自动重启。安装器必须确认当前进程完成 hook 初始化才报告成功；失败会恢复安装前的完整应用。安装后，请让另一个账号发一条新消息，等 Mac 收到后再撤回，确认消息仍然可见。安装前已经撤回的消息不会自动恢复。

气泡标记根据账号、会话及完整 64 位消息 ID 对应原消息，不通过修改正文实现。
标记数据单独保存到微信沙盒的 `Library/Application Support/WeChatIntercept/recalled-messages.json`，不修改聊天数据库；最多保存 4096 条。
它会跟随气泡滚动并避开原消息正文。无法安全放置标记或核心库 UUID 变化时，不冒险绘制，防撤回仍独立运行。
安装此标记版本之前发生的撤回没有记录 ID，无法自动补标，需用新消息测试。

---

## 命令一览

| 命令                             | 作用                                   |
| -------------------------------- | -------------------------------------- |
| `./patch.sh`                     | 安装防撤回                             |
| `./patch.sh --install`           | 安装防撤回（与无参数等价）             |
| `./patch.sh --monitor-install`   | 安装消息监听（后台自动运行，开机自启） |
| `./patch.sh --monitor-status`    | 查看监听状态                           |
| `./patch.sh --monitor-uninstall` | 卸载消息监听                           |
| `./patch.sh --uninstall`         | 卸载防撤回                             |
| `./patch.sh --help`              | 查看帮助                               |

---

## 适用范围

- macOS 微信 4.1.x（当前实测 4.1.13 build 269631；其他 build 尽力支持）
- Apple Silicon（arm64）+ Intel（x86_64）
- macOS Sequoia / Sonoma / Ventura / Tahoe

---

## 依赖

macOS 系统自带，无需额外安装：

- clang / python3 / codesign / lldb（Xcode Command Line Tools）

如未安装：`xcode-select --install`

---

## 注意事项

1. **首次运行**会保存原始整包，在临时副本编译和重签名，再替换应用并进行最多 30 秒的运行验证；验证失败会恢复安装前的应用及签名。原始备份位于 `~/Library/Application Support/WeChatIntercept/WeChat.original.app`，不要删除
2. **通知权限**：需给「脚本编辑器」开启通知权限，否则看不到弹窗  
   <img width="912" height="108" alt="image" src="https://github.com/user-attachments/assets/5865c263-7511-4b58-92a0-e69edba54f3d" />
3. **微信更新**：更新可能覆盖已注入的程序，需重新运行 `./patch.sh --install`；如果原始备份仍是旧版本，脚本会拒绝混用并停止，避免把旧版程序恢复到新版微信
4. **消息原文覆盖率**：私聊 + 大部分群聊可正常获取；部分群聊因对象结构差异会降级为不带原文（后续优化）

---

## 排查

防撤回不生效时：

```bash
log show --last 5m --style compact --predicate 'subsystem == "local.WeChatIntercept"' # hook 状态（不含聊天内容）
cat /tmp/wechat_monitor_daemon.log    # 查看消息监听日志
./patch.sh --monitor-status           # 查看监听状态
```

关键日志含义：

- `trampoline 安装成功` + 当前微信进程的 `HOOK_READY` → hook 初始化成功；仍需实际新消息测试确认效果
- `MARKER_READY` → 当前核心库的气泡标记适配器已通过类型校验
- `MARKER_RECALL_SAVED` → 已记录一条被拦截撤回的消息 ID（日志不含 ID/正文）
- `MARKER_VISIBLE count=N` → 当前已绘制 N 个气泡旁标记；消息滚出视口会隐藏
- `WARN: sender` → 当前消息布局无法安全识别，已放行此次撤回
- `hook 安装失败` → 微信版本变化较大，需更新脚本

提交 issue 时请附带微信版本和日志文件。

本地回归测试：`bash tests/run.sh`。测试只操作临时文件，覆盖特征唯一性、限长内存读取、撤回判定、跳转指令执行、撤回 XML/64 位 ID、Qt 几何/行复用、标记裁剪和双架构注入/卸载往返，不代替实际微信消息测试。

---

## 卸载

```bash
./patch.sh --monitor-uninstall   # 卸载消息监听（如安装过）
./patch.sh --uninstall           # 卸载防撤回，恢复原始微信
```

---

## 调试（开发者）

```bash
./patch.sh --debug     # 仅签名允许 lldb attach，不装 hook
./patch.sh --monitor   # 前台运行消息监听（Ctrl+C 退出）
```

---

## 风险说明

1. 微信升级后补丁可能失效，脚本内置自动寻址尽力兼容，但无法应对函数实现的根本变化
2. 当前实测版本为 4.1.13 build 269631（arm64 核心库）；其他 build 号尽力支持
3. 仅用于技术研究，请自行承担使用风险

---

## 旧版本（微信 3.7.0）

支持微信 3.7.0 及更早版本，基于 Method Swizzling，支持聊天框内撤回提示 + 自定义前缀。

<img width="301" alt="image" src="https://user-images.githubusercontent.com/18585610/159691061-3f24b69f-a494-4549-a530-7724b1b40060.png">

```bash
# 安装：将 Install.sh 拖到终端执行
# 卸载：将 Uninstall.sh 拖到终端执行
```

[微信 v3.7.0 下载](https://dldir1.qq.com/weixin/mac/WeChatMac.dmg)
