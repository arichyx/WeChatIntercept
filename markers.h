// Qt 5 消息气泡的只读适配器。所有未知地址通过 Mach 安全复制；不调用
// 私有 C++ 业务函数，不改消息对象/数据库，也不改 Qt 的 vtable。
#import <AppKit/AppKit.h>
#import <objc/message.h>
#import <stdatomic.h>

static atomic_bool gARMarkerReady = false;
static uintptr_t gARMessageInfoTable = 0;
static NSMutableDictionary<NSNumber *, NSDictionary *> *gARMetaCache;
static NSMutableSet<NSString *> *gARRecalled;
static NSMutableArray<NSString *> *gARRecallOrder;
static dispatch_queue_t gARMarkerWriter;

static uintptr_t ar_pointer(uintptr_t address) {
    uintptr_t value = 0;
    read_bytes(address, &value, sizeof(value));
    return value;
}

// 当前 libc++ alternate string layout：末字节高位区分 long/SSO。
static NSString *ar_cpp_string(uintptr_t address, size_t limit) {
    uint8_t bytes[24] = {0};
    if (!read_bytes(address, bytes, sizeof(bytes))) return nil;
    size_t length = bytes[23];
    NSData *data;
    if (length & 0x80) {
        uint64_t fields[3];
        memcpy(fields, bytes, sizeof(fields));
        length = fields[1];
        if (!fields[0] || length > limit) return nil;
        NSMutableData *copy = [NSMutableData dataWithLength:length];
        if (length && !read_bytes(fields[0], copy.mutableBytes, length)) return nil;
        data = copy;
    } else {
        if (length > 22 || length > limit) return nil;
        data = [NSData dataWithBytes:bytes length:length];
    }
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

static NSString *ar_meta_string(uintptr_t strings, uint32_t index) {
    if (index > 4096) return nil;
    uintptr_t entry = strings + index * 24;
    int32_t length = 0;
    intptr_t offset = 0;
    char bytes[256];
    if (!read_bytes(entry + 4, &length, 4) ||
        !read_bytes(entry + 16, &offset, 8) || length < 1 || length > 255 ||
        !read_bytes(entry + offset, bytes, (size_t)length)) return nil;
    return [[NSString alloc] initWithBytes:bytes length:(NSUInteger)length
                                encoding:NSUTF8StringEncoding];
}

static uintptr_t ar_qt_private(uintptr_t object) {
    if (!object) return 0;
    uintptr_t private = ar_pointer(object + 8);
    return ar_pointer(private + 8) == object ? private : 0;
}

static NSDictionary *ar_qt_meta(uintptr_t object) {
#if defined(__arm64__)
    uintptr_t private = ar_qt_private(object);
    if (!private || ar_pointer(private + 40)) return nil;
    uintptr_t table = ar_pointer(object);
    NSDictionary *cached = gARMetaCache[@(table)];
    if (cached) return cached;
    uintptr_t function = ar_pointer(table);
    uint32_t code[7];
    if (!read_bytes(function, code, sizeof(code)) || code[0] != 0xf9400400 ||
        code[1] != 0xf9401408 || (code[2] & 0xff00001f) != 0xb4000008 ||
        (code[4] & 0x9f00001f) != 0x90000000 ||
        (code[5] & 0xffc003ff) != 0x91000000 || code[6] != 0xd65f03c0) return nil;
    int64_t pages = ((code[4] >> 5) & 0x7ffff) << 2 | ((code[4] >> 29) & 3);
    if (pages & (1 << 20)) pages -= 1 << 21;
    uintptr_t meta = ((function + 16) & ~(uintptr_t)4095) + pages * 4096 +
                     ((code[5] >> 10) & 4095);
    uintptr_t data = ar_pointer(meta + 16);
    uint32_t header[2];
    if (!read_bytes(data, header, sizeof(header)) || header[0] < 7 || header[0] > 8)
        return nil;
    NSString *name = ar_meta_string(ar_pointer(meta + 8), header[1]);
    if (!name) return nil;
    NSDictionary *result = @{@"name": name, @"meta": @(meta)};
    if (gARMetaCache.count < 4096) gARMetaCache[@(table)] = result;
    return result;
#else
    return nil;
#endif
}

static BOOL ar_qt_inherits(uintptr_t object, NSString *name) {
    uintptr_t meta = [ar_qt_meta(object)[@"meta"] unsignedLongLongValue];
    for (unsigned depth = 0; meta && depth < 12; depth++, meta = ar_pointer(meta)) {
        uint32_t index;
        if (!read_bytes(ar_pointer(meta + 16) + 4, &index, 4)) return NO;
        if ([ar_meta_string(ar_pointer(meta + 8), index) isEqualToString:name]) return YES;
    }
    return NO;
}

static NSArray<NSNumber *> *ar_qt_children(uintptr_t object) {
    uintptr_t private = ar_qt_private(object);
    if (!private) return @[];
    uintptr_t list = ar_pointer(private + 24);
    int32_t header[4];
    if (!read_bytes(list, header, sizeof(header)) || header[2] < 0 ||
        header[3] < header[2] || header[3] > header[1] ||
        header[3] - header[2] > 2000) return @[];
    NSUInteger count = (NSUInteger)(header[3] - header[2]);
    NSMutableData *copy = [NSMutableData dataWithLength:count * 8];
    if (count && !read_bytes(list + 16 + header[2] * 8, copy.mutableBytes, count * 8))
        return @[];
    NSMutableArray *result = [NSMutableArray arrayWithCapacity:count];
    const uintptr_t *values = copy.bytes;
    for (NSUInteger i = 0; i < count; i++) if (values[i]) [result addObject:@(values[i])];
    return result;
}

static BOOL ar_qt_geometry(uintptr_t object, NSRect *rect) {
    uintptr_t private = ar_qt_private(object);
    uint32_t flags = 0, words[9];
    if (!private || !read_bytes(private + 32, &flags, 4) || !(flags & 1) ||
        !read_bytes(ar_pointer(object + 40), words, sizeof(words)) ||
        !(words[2] & (1 << 15)) || (words[4] & (1 << 18))) return NO;
    int32_t x = words[5], y = words[6], right = words[7], bottom = words[8];
    int64_t width = (int64_t)right - x + 1, height = (int64_t)bottom - y + 1;
    if (width < 1 || height < 1 || width > 16384 || height > 16384 ||
        x < -1000000 || x > 1000000 || y < -1000000 || y > 1000000) return NO;
    *rect = NSMakeRect(x, y, (CGFloat)width, (CGFloat)height);
    return YES;
}

static BOOL ar_qt_global_rect(uintptr_t object, uintptr_t root, NSRect *rect) {
    NSRect result, rootRect;
    if (!ar_qt_geometry(root, &rootRect) || !ar_qt_geometry(object, &result)) return NO;
    uintptr_t parent = ar_pointer(ar_qt_private(object) + 16);
    for (unsigned depth = 0; parent && depth < 30; depth++) {
        if (parent == root) { *rect = result; return YES; }
        NSRect geometry;
        if (!ar_qt_geometry(parent, &geometry)) return NO;
        result.origin.x += geometry.origin.x;
        result.origin.y += geometry.origin.y;
        parent = ar_pointer(ar_qt_private(parent) + 16);
    }
    return NO;
}

static BOOL ar_valid_session(NSString *session) {
    if (!session.length || [session lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 127)
        return NO;
    NSCharacterSet *invalid = [[NSCharacterSet characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@.-"] invertedSet];
    return [session rangeOfCharacterFromSet:invalid].location == NSNotFound;
}

static BOOL ar_decimal_id(NSString *value, uint64_t *out) {
    if (!value.length || value.length > 20) return NO;
    uint64_t result = 0;
    for (NSUInteger i = 0; i < value.length; i++) {
        unichar c = [value characterAtIndex:i];
        if (c < '0' || c > '9' || result > (UINT64_MAX - (c - '0')) / 10) return NO;
        result = result * 10 + (c - '0');
    }
    if (!result) return NO;
    *out = result;
    return YES;
}

@interface ARRecallXML : NSObject <NSXMLParserDelegate>
@property NSMutableArray<NSString *> *path;
@property NSMutableString *text;
@property NSString *session;
@property NSString *identifier;
@property BOOL invalid;
@end

@implementation ARRecallXML
- (instancetype)init {
    if ((self = [super init])) _path = [NSMutableArray array];
    return self;
}
- (void)parser:(NSXMLParser *)parser didStartElement:(NSString *)name
  namespaceURI:(NSString *)uri qualifiedName:(NSString *)qualified
    attributes:(NSDictionary<NSString *, NSString *> *)attributes {
    [_path addObject:name];
    if (_path.count == 1 && (![name isEqualToString:@"sysmsg"] ||
        ![attributes[@"type"] isEqualToString:@"revokemsg"])) _invalid = YES;
    if (_path.count > 8) { _invalid = YES; [parser abortParsing]; }
    if (_path.count == 3 && [_path[1] isEqualToString:@"revokemsg"] &&
        ([name isEqualToString:@"session"] || [name isEqualToString:@"newmsgid"]))
        _text = [NSMutableString string];
}
- (void)parser:(NSXMLParser *)parser foundCharacters:(NSString *)value {
    if (_text) [_text appendString:value];
    if (_text.length > 128) { _invalid = YES; [parser abortParsing]; }
}
- (void)parser:(NSXMLParser *)parser foundCDATA:(NSData *)value {
    if (_text) [self parser:parser foundCharacters:[[NSString alloc]
        initWithData:value encoding:NSUTF8StringEncoding] ?: @""];
}
- (void)parser:(NSXMLParser *)parser didEndElement:(NSString *)name
  namespaceURI:(NSString *)uri qualifiedName:(NSString *)qualified {
    if (_path.count == 3 && _text) {
        if ([name isEqualToString:@"session"]) {
            if (_session) _invalid = YES;
            _session = [_text copy];
        } else if ([name isEqualToString:@"newmsgid"]) {
            if (_identifier) _invalid = YES;
            _identifier = [_text copy];
        } else _invalid = YES;
        _text = nil;
    }
    if (_path.count) [_path removeLastObject];
}
@end

static NSDictionary *ar_recall_from_xml(NSString *xml) {
    if (!xml.length || [xml lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 4095 ||
        [xml rangeOfString:@"<!DOCTYPE" options:NSCaseInsensitiveSearch].location != NSNotFound)
        return nil;
    ARRecallXML *delegate = [ARRecallXML new];
    NSXMLParser *parser = [[NSXMLParser alloc] initWithData:
        [xml dataUsingEncoding:NSUTF8StringEncoding]];
    parser.shouldResolveExternalEntities = NO;
    parser.delegate = delegate;
    uint64_t identifier = 0;
    if (![parser parse] || delegate.invalid || !ar_valid_session(delegate.session) ||
        !ar_decimal_id(delegate.identifier, &identifier)) return nil;
    return @{@"session": delegate.session, @"id": @(identifier)};
}

static NSString *ar_recall_key(NSString *account, NSString *session, uint64_t identifier) {
    if (!ar_valid_session(account) || !ar_valid_session(session) || !identifier) return nil;
    return [NSString stringWithFormat:@"%@|%@|%llu", account, session,
                                     (unsigned long long)identifier];
}

static NSString *ar_message_key(uintptr_t view, NSString *account) {
    if (!ar_qt_inherits(view, @"mmui::ChatItemView")) return nil;
    uintptr_t model = ar_pointer(view + 0x230);
    if (!model || ar_pointer(model + 0x120) != gARMessageInfoTable) return nil;
    uint64_t identifier = ar_pointer(model + 0x1b0);
    NSString *session = ar_cpp_string(model + 0x160, 127);
    if (ar_pointer(view + 0x230) != model) return nil;
    return ar_recall_key(account, session, identifier);
}

@interface ARMarkerOverlay : NSView
@property(copy) NSArray<NSValue *> *badgeFrames;
@end

@implementation ARMarkerOverlay
- (BOOL)isFlipped { return YES; }
- (NSView *)hitTest:(NSPoint)point { return nil; }
- (void)drawRect:(NSRect)dirty {
    NSDictionary *attributes = @{
        NSFontAttributeName: [NSFont systemFontOfSize:10 weight:NSFontWeightMedium],
        NSForegroundColorAttributeName: NSColor.systemOrangeColor
    };
    for (NSValue *value in _badgeFrames) {
        NSRect rect = value.rectValue;
        if (!NSIntersectsRect(rect, dirty)) continue;
        [[NSColor.systemOrangeColor colorWithAlphaComponent:0.08] setFill];
        [[NSBezierPath bezierPathWithRoundedRect:rect xRadius:3 yRadius:3] fill];
        [@"已拦截撤回" drawAtPoint:NSMakePoint(rect.origin.x + 4, rect.origin.y)
                   withAttributes:attributes];
    }
}
@end

@interface ARMarkerContext : NSObject
@property(weak) NSView *host;
@property ARMarkerOverlay *overlay;
@property uintptr_t root;
@property NSArray<NSNumber *> *messageViews;
@property NSDictionary<NSNumber *, NSArray<NSNumber *> *> *items;
@property NSTimeInterval nextDiscovery;
@property NSTimeInterval nextItems;
@property BOOL touched;
@property NSUInteger visibleCount;
@end
@implementation ARMarkerContext
@end

static NSMutableArray<ARMarkerContext *> *gARMarkerContexts;

// 收集时遇到消息行便停止向下走，避免每一帧遍历整棵 Qt 控件树。
static void ar_collect(uintptr_t object, NSString *target, BOOL items,
                       NSMutableArray<NSNumber *> *result, NSMutableSet *visited,
                       unsigned depth, NSUInteger limit) {
    if (!object || depth > 30 || visited.count >= limit ||
        [visited containsObject:@(object)] || !ar_qt_private(object)) return;
    [visited addObject:@(object)];
    NSDictionary *meta = ar_qt_meta(object);
    if ((items && ar_qt_inherits(object, target)) ||
        (!items && [meta[@"name"] isEqualToString:target])) {
        [result addObject:@(object)];
        return;
    }
    for (NSNumber *child in ar_qt_children(object))
        ar_collect(child.unsignedLongLongValue, target, items, result, visited,
                   depth + 1, limit);
}

static NSRect ar_bubble_rect(uintptr_t item, uintptr_t root) {
    NSMutableArray *frames = [NSMutableArray array];
    // 外层 ChatBubbleFrame 包括引用区域；标记靠它的边缘，不侵入正文。
    ar_collect(item, @"mmui::ChatBubbleFrame", NO, frames,
               [NSMutableSet set], 0, 200);
    NSRect best = NSZeroRect;
    for (NSNumber *frame in frames) {
        NSRect rect;
        if (ar_qt_global_rect(frame.unsignedLongLongValue, root, &rect) &&
            rect.size.width * rect.size.height > best.size.width * best.size.height)
            best = rect;
    }
    return best;
}

static NSRect ar_badge_rect(NSRect bubble, NSRect cell, NSRect viewport,
                            NSArray<NSValue *> *otherBubbles) {
    if (NSIsEmptyRect(bubble)) return NSZeroRect;
    NSRect rect = NSMakeRect(NSMaxX(bubble) + 6, NSMidY(bubble) - 7, 68, 14);
    if (!NSContainsRect(viewport, rect)) {
        rect = NSMakeRect(NSMinX(bubble), NSMaxY(bubble) + 1, 68, 14);
        if (NSMaxY(rect) > NSMaxY(cell) + 3 || !NSContainsRect(viewport, rect))
            return NSZeroRect;
    }
    for (NSValue *value in otherBubbles) {
        if (NSIntersectsRect(rect, value.rectValue)) return NSZeroRect;
    }
    return rect;
}

static uintptr_t ar_root_for_host(NSView *host) {
    if (![host isKindOfClass:NSClassFromString(@"QNSView")] ||
        ![host respondsToSelector:sel_getUid("platformWindow")]) return 0;
    uintptr_t platform = (uintptr_t)((void *(*)(id, SEL))objc_msgSend)
        (host, sel_getUid("platformWindow"));
    if (!ar_qt_private(platform)) return 0;
    uintptr_t surface = ar_pointer(platform + 24);
    if (surface < 16) return 0;
    uintptr_t window = surface - 16;
    if (![ar_qt_meta(window)[@"name"] isEqualToString:@"QWidgetWindow"]) return 0;
    uintptr_t root = ar_pointer(window + 48);
    return ar_qt_inherits(root, @"QWidget") ? root : 0;
}

static void ar_update_context(ARMarkerContext *context, NSString *account,
                               NSTimeInterval now) {
    NSView *host = context.host;
    uintptr_t root = ar_root_for_host(host);
    if (!root) { context.overlay.hidden = YES; return; }
    if (context.root != root) {
        context.root = root;
        context.nextDiscovery = context.nextItems = 0;
    }
    if (now >= context.nextDiscovery) {
        NSMutableArray *views = [NSMutableArray array];
        ar_collect(root, @"mmui::MessageView", NO, views,
                   [NSMutableSet set], 0, 5000);
        context.messageViews = views;
        context.nextDiscovery = now + 2;
        context.nextItems = 0;
    }
    if (now >= context.nextItems) {
        NSMutableDictionary *items = [NSMutableDictionary dictionary];
        for (NSNumber *view in context.messageViews) {
            NSMutableArray *rows = [NSMutableArray array];
            ar_collect(view.unsignedLongLongValue, @"mmui::ChatItemView", YES,
                       rows, [NSMutableSet set], 0, 2000);
            items[view] = rows;
        }
        context.items = items;
        context.nextItems = now + 0.4;
    }
    NSMutableArray *badges = [NSMutableArray array];
    for (NSNumber *view in context.messageViews) {
        NSRect viewport;
        if (!ar_qt_global_rect(view.unsignedLongLongValue, root, &viewport)) continue;
        viewport = NSIntersectionRect(viewport, host.bounds);
        if (NSIsEmptyRect(viewport)) continue;
        NSArray *rows = context.items[view];
        NSMutableArray *marked = [NSMutableArray array], *allBubbles = [NSMutableArray array];
        // 先判断是否有匹配 ID。无匹配时不计算各行的气泡坐标。
        for (NSNumber *row in rows) {
            NSString *key = ar_message_key(row.unsignedLongLongValue, account);
            if (key && [gARRecalled containsObject:key]) [marked addObject:row];
        }
        if (!marked.count) continue;
        NSMutableDictionary *bubbleRects = [NSMutableDictionary dictionary];
        for (NSNumber *row in rows) {
            NSRect rect = ar_bubble_rect(row.unsignedLongLongValue, root);
            if (!NSIsEmptyRect(rect) && NSIntersectsRect(rect, viewport)) {
                NSValue *value = [NSValue valueWithRect:rect];
                bubbleRects[row] = value;
                [allBubbles addObject:value];
            }
        }
        for (NSNumber *row in marked) {
            NSRect cell;
            if (!ar_qt_global_rect(row.unsignedLongLongValue, root, &cell)) continue;
            NSValue *bubbleValue = bubbleRects[row];
            if (!bubbleValue) continue;
            NSRect bubble = bubbleValue.rectValue;
            // 气泡离开滚动视口时立刻隐藏，不能漂到输入框/标题栏。
            if (!NSIntersectsRect(bubble, viewport)) continue;
            NSRect badge = ar_badge_rect(bubble, cell, viewport, allBubbles);
            if (!NSIsEmptyRect(badge)) [badges addObject:[NSValue valueWithRect:badge]];
        }
    }
    if (!context.overlay && badges.count) {
        ARMarkerOverlay *overlay = [[ARMarkerOverlay alloc] initWithFrame:host.bounds];
        overlay.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
        [host addSubview:overlay positioned:NSWindowAbove relativeTo:nil];
        context.overlay = overlay;
    }
    if (![context.overlay.badgeFrames isEqualToArray:badges]) {
        context.overlay.badgeFrames = badges;
        context.overlay.needsDisplay = YES;
    }
    context.overlay.hidden = badges.count == 0;
    if (context.visibleCount != badges.count) {
        context.visibleCount = badges.count;
        ARLOG("MARKER_VISIBLE count=%lu", (unsigned long)badges.count);
    }
}

static void ar_marker_tick(void) {
    if (!gARMarkerReady || !gARRecalled.count || !g_my_id[0]) return;
    NSString *account = [NSString stringWithUTF8String:g_my_id];
    NSTimeInterval now = NSDate.timeIntervalSinceReferenceDate;
    for (ARMarkerContext *context in [gARMarkerContexts copy]) {
        if (!context.host) {
            [context.overlay removeFromSuperview];
            [gARMarkerContexts removeObject:context];
        } else context.touched = NO;
    }
    Class qnsClass = NSClassFromString(@"QNSView");
    for (NSWindow *window in NSApp.windows) {
        NSView *host = window.contentView;
        if (!window.isVisible || window.isMiniaturized || ![host isKindOfClass:qnsClass]) continue;
        ARMarkerContext *context = nil;
        for (ARMarkerContext *candidate in gARMarkerContexts)
            if (candidate.host == host) { context = candidate; break; }
        if (!context) {
            context = [ARMarkerContext new];
            context.host = host;
            [gARMarkerContexts addObject:context];
        }
        context.touched = YES;
        ar_update_context(context, account, now);
    }
    for (ARMarkerContext *context in gARMarkerContexts)
        if (!context.touched) context.overlay.hidden = YES;
}

static NSString *ar_marker_file(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:
        @"Library/Application Support/WeChatIntercept/recalled-messages.json"];
}

static BOOL ar_valid_stored_key(NSString *key) {
    if (![key isKindOfClass:NSString.class] || key.length > 300) return NO;
    NSArray *parts = [key componentsSeparatedByString:@"|"];
    uint64_t identifier = 0;
    return parts.count == 3 && ar_valid_session(parts[0]) &&
        ar_valid_session(parts[1]) && ar_decimal_id(parts[2], &identifier);
}

static void ar_marker_record_xml(const char *xml) {
#ifndef WECHATINTERCEPT_TEST
    if (!gARMarkerReady || !xml || !g_my_id[0]) return;
    @autoreleasepool {
        NSDictionary *recall = ar_recall_from_xml([NSString stringWithUTF8String:xml]);
        NSString *key = recall ? ar_recall_key([NSString stringWithUTF8String:g_my_id],
            recall[@"session"], [recall[@"id"] unsignedLongLongValue]) : nil;
        if (!key) { ARLOG("WARN: 撤回标记缺少可验证的消息 ID/会话"); return; }
        dispatch_async(dispatch_get_main_queue(), ^{
            if ([gARRecalled containsObject:key]) return;
            [gARRecalled addObject:key];
            [gARRecallOrder addObject:key];
            while (gARRecallOrder.count > 4096) {
                [gARRecalled removeObject:gARRecallOrder.firstObject];
                [gARRecallOrder removeObjectAtIndex:0];
            }
            NSData *data = [NSJSONSerialization dataWithJSONObject:gARRecallOrder
                options:0 error:NULL];
            dispatch_async(gARMarkerWriter, ^{
                NSString *file = ar_marker_file();
                [[NSFileManager defaultManager] createDirectoryAtPath:
                    file.stringByDeletingLastPathComponent withIntermediateDirectories:YES
                    attributes:@{NSFilePosixPermissions: @0700} error:NULL];
                if (![data writeToFile:file atomically:YES])
                    ARLOG("WARN: 撤回标记持久化失败，本次仍保留内存标记");
                else [[NSFileManager defaultManager] setAttributes:
                    @{NSFilePosixPermissions: @0600} ofItemAtPath:file error:NULL];
            });
            ARLOG("MARKER_RECALL_SAVED");
            ar_marker_tick();
        });
    }
#endif
}

static BOOL ar_marker_supported_core(const struct mach_header *header) {
#if defined(__arm64__)
    // 只启用已核验的核心库，升级后关闭界面适配器，不能猜字段偏移。
    const uint8_t expected[16] = {
        0x91,0x8f,0xfb,0xfd,0xe1,0x8d,0x36,0x3f,
        0xb0,0x7c,0xb8,0xd7,0xf1,0x43,0x67,0x27
    };
    if (!header || header->magic != MH_MAGIC_64) return NO;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)header;
    const uint8_t *cursor = (const uint8_t *)(mh + 1), *end = cursor + mh->sizeofcmds;
    for (uint32_t i = 0; i < mh->ncmds && cursor + sizeof(struct load_command) <= end; i++) {
        const struct load_command *command = (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command) || cursor + command->cmdsize > end) return NO;
        if (command->cmd == LC_UUID && command->cmdsize == sizeof(struct uuid_command))
            return memcmp(((const struct uuid_command *)command)->uuid, expected, 16) == 0;
        cursor += command->cmdsize;
    }
#endif
    return NO;
}

static void ar_marker_start(const struct mach_header *header, uintptr_t slide) {
#ifndef WECHATINTERCEPT_TEST
    if (gARMarkerReady) return;
    if (!ar_marker_supported_core(header)) {
        ARLOG("WARN: 当前核心库未适配气泡标记，防撤回仍独立工作");
        return;
    }
    gARMessageInfoTable = slide + 0x99f5260;
    // 检查 MessageInfo 的 sized-delete 指令：该类型为 0x350 字节。
    uint32_t code[4];
    if (!read_bytes(ar_pointer(gARMessageInfoTable + 8), code, sizeof(code)) ||
        code[0] != 0xa9bf7bfd || code[1] != 0x910003fd || code[3] != 0x52806a01) {
        ARLOG("WARN: 消息记录类型校验失败，关闭气泡标记");
        return;
    }
    gARMetaCache = [NSMutableDictionary dictionary];
    gARRecalled = [NSMutableSet set];
    gARRecallOrder = [NSMutableArray array];
    gARMarkerContexts = [NSMutableArray array];
    gARMarkerWriter = dispatch_queue_create("local.WeChatIntercept.marker-writer", DISPATCH_QUEUE_SERIAL);
    NSData *data = [NSData dataWithContentsOfFile:ar_marker_file()];
    if (data.length && data.length <= 1024 * 1024) {
        id saved = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
        if ([saved isKindOfClass:NSArray.class]) {
            for (id key in saved) if (ar_valid_stored_key(key) &&
                gARRecallOrder.count < 4096 && ![gARRecalled containsObject:key]) {
                [gARRecalled addObject:key];
                [gARRecallOrder addObject:key];
            }
        }
    }
    gARMarkerReady = YES;
    NSTimer *timer = [NSTimer timerWithTimeInterval:0.1 repeats:YES block:
        ^(NSTimer *unused) { @autoreleasepool { ar_marker_tick(); } }];
    [[NSRunLoop mainRunLoop] addTimer:timer forMode:NSRunLoopCommonModes];
    ARLOG("MARKER_READY");
#endif
}
