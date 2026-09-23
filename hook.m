#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <sys/mman.h>
#import <libkern/OSCacheControl.h>
#import <stdint.h>
#import <string.h>
#import <stdio.h>
#import <sys/stat.h>
#import <unistd.h>
#import <os/log.h>

static FILE *g_logFile = NULL;
static os_log_t g_statusLog = NULL;

static void log_open(void) {
    g_statusLog = os_log_create("local.WeChatIntercept", "hook");
    // 写入微信自己的沙盒，而不是依赖全局 /tmp 的写权限。
    @autoreleasepool {
        NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Logs/WeChatIntercept"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
            withIntermediateDirectories:YES attributes:nil error:NULL];
        g_logFile = fopen([[dir stringByAppendingPathComponent:@"hook.log"] fileSystemRepresentation], "a");
    }
}

#define ARLOG(fmt, ...) do { \
    char line[1024]; \
    snprintf(line, sizeof(line), "[AntiRevoke pid=%d] " fmt, getpid(), ##__VA_ARGS__); \
    if (g_logFile) { fprintf(g_logFile, "%s\n", line); fflush(g_logFile); } \
    if (g_statusLog) { os_log_with_type(g_statusLog, OS_LOG_TYPE_DEFAULT, "%{public}s", line); } \
} while(0)

// 注意：Resources/wechat.dylib 是核心库（~140MB），Frameworks/ 下是 stub（~16KB），不能 hook 错
static const char    *kDylibSuffix_Resources  = "Resources/wechat.dylib";
static const int32_t  kRevokeType    = 0x2712;   // isRevokeMessage 比较的 MsgType 常量



// 当前登录用户 wxid，用于区分"自己撤回"vs"对方撤回"
static char g_my_id[64] = {0};
static _Bool g_my_id_loaded = 0;

// 通过取 ~/Library/Containers/.../app_data/login/ 下最新修改的目录名判定
static void load_my_user_id(void) {
    if (g_my_id_loaded) return;
    g_my_id_loaded = 1;

    @autoreleasepool {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *dirPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/app_data/login"];
        NSArray *contents = [fm contentsOfDirectoryAtPath:dirPath error:nil];
        if (!contents || [contents count] == 0) return;

        NSString *latestName = nil;
        NSDate *latestDate = nil;

        for (NSString *name in contents) {
            if ([name hasPrefix:@"."]) continue;
            NSString *fullPath = [dirPath stringByAppendingPathComponent:name];
            BOOL isDir = NO;
            if (![fm fileExistsAtPath:fullPath isDirectory:&isDir] || !isDir) continue;

            NSString *keyInfo = [fullPath stringByAppendingPathComponent:@"key_info.dat"];
            NSDictionary *attrs = [fm fileExistsAtPath:keyInfo]
                ? [fm attributesOfItemAtPath:keyInfo error:nil]
                : [fm attributesOfItemAtPath:fullPath error:nil];
            NSDate *modDate = attrs[NSFileModificationDate];

            if (!latestDate || (modDate && [modDate compare:latestDate] == NSOrderedDescending)) {
                latestDate = modDate;
                latestName = name;
            }
        }

        if (latestName && [latestName length] >= 3 && [latestName length] < sizeof(g_my_id)) {
            strncpy(g_my_id, [latestName UTF8String], sizeof(g_my_id) - 1);
            ARLOG("登录用户标识已读取");
        }
    }
}



static void send_notification(const char *text) {
    // osascript 对 " 和 \ 敏感，必须转义
    char *escaped = (char *)malloc(1024);
    if (!escaped) return;
    int j = 0;
    for (int i = 0; text[i] && j < 1022; i++) {
        if (text[i] == '"' || text[i] == '\\') escaped[j++] = '\\';
        escaped[j++] = text[i];
    }
    escaped[j] = '\0';

    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        FILE *sf = fopen("/tmp/antirevoke_notify.scpt", "w");
        if (sf) {
            fprintf(sf, "display notification \"%s\" with title \"WeChatIntercept\"\n", escaped);
            fclose(sf);
            system("osascript /tmp/antirevoke_notify.scpt");
        }
        free(escaped);
    });
}

// 微信小版本升级 sender 偏移可能漂移；仅检查前 4 字节是否可打印 ASCII
// 失效时静默放行（return 1），不影响微信内部撤回流程；阈值后弹一次催更新通知
static _Bool is_valid_sender(const char *s) {
    if (s[0] == '\0') return 1;  // 空 = 自己撤回的内部回调
    for (int i = 0; i < 4; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c > 0x7E) return 0;
    }
    return 1;
}

// 小版本升级可能改变对象布局；先安全、限长地复制，不直接解引用未知 XML 指针。
static _Bool read_bytes(uintptr_t addr, void *out, size_t len) {
    mach_vm_size_t copied = 0;
    return mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)addr, len,
        (mach_vm_address_t)out, &copied) == KERN_SUCCESS && copied == len;
}

// stickers.h 的微信 4 Qt 菜单适配器在本文件后面定义的通用跳板上安装钩子。
static _Bool install_arm64_trampoline(uintptr_t func_addr, uintptr_t hook_addr);

#include "markers.h"
#include "stickers.h"

// 入口：被微信 isRevokeMessage 替换。
// 返回 1 = 该消息是撤回（按原行为处理）；返回 0 = 阻止微信删除消息
__attribute__((visibility("default")))
_Bool hook_isRevokeMessage(void *msg) {
    if (msg == NULL) return 0;

    int32_t msgType = 0;
    if (!read_bytes((uintptr_t)msg + 0x0C, &msgType, sizeof(msgType))) return 0;
    if (msgType != kRevokeType) return 0;

    load_my_user_id();

    // 动态寻址 sender 字符串：+0x18 在新 build 中可能是标记字节
    // 从 +0x18 开始搜第一个可打印 C 字符串
    unsigned char sender_region[72] = {0};
    if (!read_bytes((uintptr_t)msg + 0x18, sender_region, sizeof(sender_region))) {
        ARLOG("WARN: sender 区域不可读，放行此次撤回");
        return 1;
    }
    int sender_off = 0;
    {
        int found = 0;
        for (int off = 0; off <= 8; off++) {
            const unsigned char *p = sender_region + off;
            if (p[0] >= 0x20 && p[0] <= 0x7E &&
                p[1] >= 0x20 && p[1] <= 0x7E &&
                p[2] >= 0x20 && p[2] <= 0x7E) {
                sender_off = off;
                found = 1;
                break;
            }
        }
        if (!found) {
            // 极端 fallback 仍然用 +0x18
            sender_off = 0;
        }
    }
    char sender[64] = {0};
    size_t sender_len = strnlen((const char *)sender_region + sender_off, sizeof(sender) - 1);
    if (sender_len == sizeof(sender) - 1) {
        ARLOG("WARN: sender 未找到字符串结束符，放行此次撤回");
        return 1;
    }
    memcpy(sender, sender_region + sender_off, sender_len);

    if (!is_valid_sender(sender)) {
        ARLOG("WARN: sender 区域非可打印 ASCII，跳过此次调用");
        static int g_invalid_count = 0;
        static _Bool g_warned = 0;
        g_invalid_count++;
        if (g_invalid_count >= 5 && !g_warned) {
            g_warned = 1;
            char *cmd = (char *)malloc(1024);
            if (cmd) {
                snprintf(cmd, 1024,
                    "osascript -e 'display notification \"sender 偏移已失效，快去催 WeChatIntercept 作者更新适配\" "
                    "with title \"WeChatIntercept 需更新\"' &");
                dispatch_async(dispatch_get_global_queue(0, 0), ^{
                    system(cmd);
                    free(cmd);
                });
            }
        }
        return 1;
    }

    // 自己撤回 → 放行（让微信正常处理）
    if (sender[0] == '\0') return 1;
    if (g_my_id[0] != '\0' && strcmp(sender, g_my_id) == 0) return 1;

    // 对方撤回 → 阻止
    ARLOG("拦截到撤回请求");

    // 从 msg+0x130 (ptr) / +0x138 (len) 读撤回 XML
    char notify_text[256] = {0};

#if defined(__arm64__) || defined(__aarch64__)
    uint64_t xml_fields[2] = {0};
    char xml_body[4096] = {0};
    _Bool has_xml = read_bytes((uintptr_t)msg + 0x130, xml_fields, sizeof(xml_fields)) &&
        xml_fields[0] != 0 && xml_fields[1] > 0 && xml_fields[1] < sizeof(xml_body) &&
        read_bytes(xml_fields[0], xml_body, (size_t)xml_fields[1]);
    if (has_xml) {
        ar_marker_record_xml(xml_body);
        // CDATA 内容形如 "Macanzy" 撤回了一条消息
        const char *cs = strstr(xml_body, "<![CDATA[");
        const char *ce = cs ? strstr(cs, "]]>") : NULL;
        if (cs && ce) {
            cs += 9;
            size_t len = ce - cs;
            if (len > 0 && len < sizeof(notify_text) - 1) {
                memcpy(notify_text, cs, len);
                notify_text[len] = '\0';
            }
        }
    }
#endif

    // 反查 lldb monitor 写入的消息缓存（/tmp/wechat_msg_cache.tsv）
    char orig_content[512] = {0};
    _Bool has_orig = 0;
#if defined(__arm64__) || defined(__aarch64__)
    if (has_xml) {
        const char *p = strstr(xml_body, "<newmsgid>");
        uint64_t newmsgid = 0;
        if (p) {
            p += 10;
            int digits = 0;
            while (*p >= '0' && *p <= '9' && digits < 20) {
                newmsgid = newmsgid * 10 + (uint64_t)(*p - '0');
                p++; digits++;
            }
            if (digits == 0) newmsgid = 0;
        }
        if (newmsgid != 0) {
            FILE *cf = fopen("/tmp/wechat_msg_cache.tsv", "r");
            if (cf) {
                char line[1024];
                while (fgets(line, sizeof(line), cf)) {
                    char *t1 = strchr(line, '\t');
                    if (!t1) continue;
                    *t1 = '\0';
                    uint64_t row_svrid = 0;
                    int d2 = 0;
                    for (const char *q = line; *q >= '0' && *q <= '9' && d2 < 20; q++, d2++)
                        row_svrid = row_svrid * 10 + (uint64_t)(*q - '0');
                    if (d2 == 0 || row_svrid != newmsgid) continue;
                    char *t2 = strchr(t1 + 1, '\t');
                    if (!t2) continue;
                    char *nl = strchr(t2 + 1, '\n');
                    if (nl) *nl = '\0';
                    strncpy(orig_content, t2 + 1, sizeof(orig_content) - 1);
                    has_orig = (orig_content[0] != '\0');
                }
                fclose(cf);
            }
            ARLOG("撤回原文缓存%s", has_orig ? "命中" : "未命中");
        }
    }
#endif

    // 非文本消息描述模板 → 占位符
    if (has_orig) {
        struct { const char *needle; const char *replace; } kReplaces[] = {
            {"发了一张图片", "[图片]"}, {"发了一段视频", "[视频]"},
            {"发了一个文件", "[文件]"}, {"发了一段语音", "[语音]"},
            {"发了一条语音消息", "[语音]"}, {"发了一个表情", "[表情]"},
            {"发了一个视频号", "[视频号]"}, {"发了一张名片", "[名片]"},
            {"发了一个位置", "[位置]"}, {"发了一个红包", "[红包]"},
            {"发了一个链接", "[链接]"}, {"发了一个小程序", "[小程序]"},
            {NULL, NULL},
        };
        for (int i = 0; kReplaces[i].needle; i++) {
            if (strstr(orig_content, kReplaces[i].needle)) {
                strncpy(orig_content, kReplaces[i].replace, sizeof(orig_content) - 1);
                break;
            }
        }
    }

    // 从 notify_text 抽纯昵称：剥 "撤回了" 后缀 + 首尾空格 + 英文双引号
    char nick[128] = {0};
    if (notify_text[0] != '\0') {
        const char *p = strstr(notify_text, "撤回了");
        if (p && p > notify_text) {
            const char *start = notify_text;
            size_t nlen = (size_t)(p - notify_text);
            while (nlen > 0 && start[nlen - 1] == ' ') nlen--;
            while (nlen > 0 && *start == ' ') { start++; nlen--; }
            if (nlen >= 2 && start[0] == '"' && start[nlen - 1] == '"') { start++; nlen -= 2; }
            if (nlen > 0 && nlen < sizeof(nick)) { memcpy(nick, start, nlen); nick[nlen] = '\0'; }
        }
    }
    const char *who = (nick[0] != '\0') ? nick : sender;

    char content[768] = {0};
    if (has_orig) {
        snprintf(content, sizeof(content), "拦截到「%s」撤回了一条消息：%s", who, orig_content);
    } else {
        snprintf(content, sizeof(content), "拦截到「%s」撤回了一条消息", who);
    }

#ifndef WECHATINTERCEPT_TEST
    send_notification(content);
#endif

    return 0;
}

// ── 查找 wechat.dylib 的 ASLR slide 和 mach_header ───────────
// 优先匹配 Resources/wechat.dylib（核心库），Frameworks/ 为 stub 不可用
static uintptr_t find_wechat_slide(const struct mach_header **out_header) {
    uint32_t count = _dyld_image_count();
    size_t resLen = strlen(kDylibSuffix_Resources);

    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        size_t len = strlen(name);
        if (len >= resLen && strcmp(name + len - resLen, kDylibSuffix_Resources) == 0) {
            if (out_header) *out_header = _dyld_get_image_header(i);
            return (uintptr_t)_dyld_get_image_vmaddr_slide(i);
        }
    }
    if (out_header) *out_header = NULL;
    return 0;
}

static _Bool find_text_segment(const struct mach_header *header, uintptr_t slide,
                                uintptr_t *out_start, size_t *out_size) {
    if (!header) return 0;

    const uint8_t *p = (const uint8_t *)header;
    uint32_t ncmds;
    if (header->magic == MH_MAGIC_64) {
        p += sizeof(struct mach_header_64);
        ncmds = ((const struct mach_header_64 *)header)->ncmds;
    } else if (header->magic == MH_MAGIC) {
        p += sizeof(struct mach_header);
        ncmds = header->ncmds;
    } else {
        return 0;
    }

    for (uint32_t i = 0; i < ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)p;
            if (strcmp(seg->segname, "__TEXT") == 0) {
                const struct section_64 *sections = (const struct section_64 *)(seg + 1);
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (strcmp(sections[j].sectname, "__text") == 0) {
                        *out_start = (uintptr_t)sections[j].addr + slide;
                        *out_size = (size_t)sections[j].size;
                        return 1;
                    }
                }
            }
        } else if (lc->cmd == LC_SEGMENT) {
            const struct segment_command *seg = (const struct segment_command *)p;
            if (strcmp(seg->segname, "__TEXT") == 0) {
                *out_start = (uintptr_t)seg->vmaddr + slide;
                *out_size = (size_t)seg->vmsize;
                return 1;
            }
        }
        p += lc->cmdsize;
    }
    return 0;
}

// arm64 isRevokeMessage 特征码：LDR W8,[X0,#C]; MOV W9,#0x2712; CMP; CSET; RET
static uintptr_t scan_isRevokeMessage_arm64(uintptr_t text_start, size_t text_size) {
    static const uint32_t pattern[5] = {
        0xB9400C08u, 0x5284E249u, 0x6B09011Fu, 0x1A9F17E0u, 0xD65F03C0u
    };
    const uint32_t *base = (const uint32_t *)text_start;
    size_t count = text_size / 4;
    if (count < 5) return 0;

    uintptr_t found = 0;
    for (size_t i = 0; i + 5 <= count; i++) {
        if (base[i]   == pattern[0] &&
            base[i+1] == pattern[1] &&
            base[i+2] == pattern[2] &&
            base[i+3] == pattern[3] &&
            base[i+4] == pattern[4]) {
            if (found) { ARLOG("ERROR: arm64 特征码不唯一，拒绝 hook"); return 0; }
            found = text_start + i * 4;
        }
    }
    return found;
}

// x86_64 isRevokeMessage 特征码
static uintptr_t scan_isRevokeMessage_x86_64(uintptr_t text_start, size_t text_size) {
    static const uint8_t pattern[] = {
        0x55, 0x48, 0x89, 0xE5,
        0x81, 0x7F, 0x0C, 0x12, 0x27, 0x00, 0x00,
        0x0F, 0x94, 0xC0,
        0x5D, 0xC3
    };
    const uint8_t *base = (const uint8_t *)text_start;
    if (text_size < sizeof(pattern)) return 0;

    uintptr_t found = 0;
    for (size_t i = 0; i + sizeof(pattern) <= text_size; i++) {
        if (base[i] == pattern[0] &&
            memcmp(base + i, pattern, sizeof(pattern)) == 0) {
            if (found) { ARLOG("ERROR: x86_64 特征码不唯一，拒绝 hook"); return 0; }
            found = text_start + i;
        }
    }
    return found;
}

static const char *kKnownBuilds[] = { "268602", "268824", "269631", NULL };

static _Bool is_known_build(const char *build) {
    if (!build) return 0;
    for (int i = 0; kKnownBuilds[i]; i++) {
        if (strcmp(build, kKnownBuilds[i]) == 0) return 1;
    }
    return 0;
}

static void read_wechat_version(char *short_ver, size_t short_sz,
                                  char *build, size_t build_sz) {
    short_ver[0] = '\0';
    build[0] = '\0';
    @autoreleasepool {
        NSDictionary *info = [[NSBundle mainBundle] infoDictionary];
        NSString *sv = info[@"CFBundleShortVersionString"];
        NSString *bv = info[@"CFBundleVersion"];
        if (sv) strncpy(short_ver, [sv UTF8String], short_sz - 1);
        if (bv) strncpy(build, [bv UTF8String], build_sz - 1);
    }
}

static kern_return_t make_rw(uintptr_t addr, size_t len) {
    uintptr_t mask = (uintptr_t)getpagesize() - 1;
    uintptr_t page = addr & ~mask;
    size_t sz = (addr + len - page + mask) & ~mask;
    return vm_protect(mach_task_self(), (vm_address_t)page, sz, 0,
                      VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
}
static kern_return_t make_rx(uintptr_t addr, size_t len) {
    uintptr_t mask = (uintptr_t)getpagesize() - 1;
    uintptr_t page = addr & ~mask;
    size_t sz = (addr + len - page + mask) & ~mask;
    return vm_protect(mach_task_self(), (vm_address_t)page, sz, 0,
                      VM_PROT_READ | VM_PROT_EXECUTE);
}

// Exactly 16 bytes: gateways replay four instructions and resume at +16.
// An extra NOP at +16 would erase the first unreplayed instruction.
static _Bool install_arm64_trampoline(uintptr_t func_addr, uintptr_t hook_addr) {
    kern_return_t kr = make_rw(func_addr, 16);
    if (kr != KERN_SUCCESS) { ARLOG("ERROR: make_rw kr=%d", kr); return 0; }

    uint32_t *p = (uint32_t *)func_addr;
    p[0] = 0x58000050u;  // LDR X16, #8
    p[1] = 0xD61F0200u;  // BR X16
    *(uint64_t *)(func_addr + 8) = (uint64_t)hook_addr;

    // 回读验证
    if (*(volatile uint32_t *)func_addr != 0x58000050u) {
        ARLOG("ERROR: 写入验证失败"); return 0;
    }

    sys_icache_invalidate((void *)func_addr, 16);
    kr = make_rx(func_addr, 16);
    if (kr != KERN_SUCCESS) { ARLOG("ERROR: make_rx kr=%d", kr); return 0; }
    return 1;
}

// x86_64: JMP [RIP+0]; <addr64>; NOP; RET  — 共 16 字节
static _Bool install_x86_64_trampoline(uintptr_t func_addr, uintptr_t hook_addr) {
    kern_return_t kr = make_rw(func_addr, 16);
    if (kr != KERN_SUCCESS) { ARLOG("ERROR: x86_64 make_rw kr=%d", kr); return 0; }

    uint8_t *p = (uint8_t *)func_addr;
    p[0] = 0xFF; p[1] = 0x25;  // JMP [RIP+0]
    p[2] = p[3] = p[4] = p[5] = 0x00;
    *(uint64_t *)(func_addr + 6) = (uint64_t)hook_addr;
    p[14] = 0x90; p[15] = 0xC3;

    if (*(volatile uint8_t *)func_addr != 0xFF) {
        ARLOG("ERROR: x86_64 写入验证失败"); return 0;
    }

    __builtin___clear_cache((char *)func_addr, (char *)(func_addr + 16));
    kr = make_rx(func_addr, 16);
    if (kr != KERN_SUCCESS) { ARLOG("ERROR: x86_64 make_rx kr=%d", kr); return 0; }
    return 1;
}

static void notify_install_failed(const char *short_ver, const char *build, _Bool known_build) {

    char *cmd = (char *)malloc(2048);
    if (!cmd) return;

    char title[64];
    char body[512];

    if (known_build) {
        snprintf(title, sizeof(title), "WeChatIntercept 异常");
        snprintf(body, sizeof(body),
            "已知版本 %s (%s) hook 安装失败，请查看系统日志 local.WeChatIntercept",
            short_ver, build);
    } else {
        snprintf(title, sizeof(title), "WeChatIntercept 需更新");
        snprintf(body, sizeof(body),
            "微信版本 %s (build %s) 未适配，防撤回功能已失效。请前往 GitHub 获取最新脚本",
            short_ver, build);
    }

    char escaped[1024];
    int j = 0;
    for (int i = 0; body[i] && j < (int)sizeof(escaped) - 2; i++) {
        if (body[i] == '"' || body[i] == '\\') escaped[j++] = '\\';
        escaped[j++] = body[i];
    }
    escaped[j] = '\0';

    snprintf(cmd, 2048,
        "osascript -e 'display notification \"%s\" with title \"%s\"' &",
        escaped, title);

    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        system(cmd);
        free(cmd);
    });
}

// libwxld 在启动时动态加载核心库；不能假定本库 constructor 执行时它已存在。
static void try_install_hook(unsigned attempt) {
    const struct mach_header *header = NULL;
    uintptr_t slide = find_wechat_slide(&header);
    if (!header && attempt < 20) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC / 2),
            dispatch_get_main_queue(), ^{ try_install_hook(attempt + 1); });
        return;
    }

    char short_ver[32] = {0};
    char build[32] = {0};
    read_wechat_version(short_ver, sizeof(short_ver), build, sizeof(build));
    _Bool known_build = is_known_build(build);
    ARLOG("微信版本: %s (build %s)", short_ver, build);
    if (!header) {
        ARLOG("ERROR: 未找到 Resources/wechat.dylib");
        notify_install_failed(short_ver, build, known_build);
        return;
    }

    uintptr_t text_start = 0;
    size_t text_size = 0;
    if (!find_text_segment(header, slide, &text_start, &text_size)) {
        ARLOG("ERROR: 未找到核心库 __text");
        return;
    }
    ARLOG("slide=0x%lx __text=[0x%lx, +0x%zx)",
        (unsigned long)slide, (unsigned long)text_start, text_size);

    uintptr_t func_addr = 0;
    _Bool installed = 0;
    load_my_user_id();
#if defined(__arm64__) || defined(__aarch64__)
    func_addr = scan_isRevokeMessage_arm64(text_start, text_size);
    if (func_addr) {
        ar_marker_start(header, slide);
        if (gARMarkerReady) ar_sticker_start(header, slide);
        installed = install_arm64_trampoline(func_addr, (uintptr_t)&hook_isRevokeMessage);
    }
#elif defined(__x86_64__)
    func_addr = scan_isRevokeMessage_x86_64(text_start, text_size);
    if (func_addr) installed = install_x86_64_trampoline(func_addr, (uintptr_t)&hook_isRevokeMessage);
#endif
    if (!installed) {
        ARLOG("ERROR: hook 安装失败（无唯一特征或代码页写入失败）");
        notify_install_failed(short_ver, build, known_build);
        return;
    }
    ARLOG("trampoline 安装成功 offset=0x%lx", (unsigned long)(func_addr - slide));
    ARLOG("HOOK_READY");
}

#ifndef WECHATINTERCEPT_TEST
__attribute__((constructor))
static void hook_init(void) {
    log_open();
    ARLOG("constructor 已执行");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC),
        dispatch_get_main_queue(), ^{ try_install_hook(0); });
}
#endif
