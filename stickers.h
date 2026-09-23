// 微信 4.1.13 arm64 表情导出适配器。只在已校验的 Qt/MessageInfo 布局上启用；
// 未知版本安全关闭，不修改消息对象、聊天数据库或 Qt vtable。
#import <AppKit/AppKit.h>
#import <ImageIO/ImageIO.h>
#import <CommonCrypto/CommonCryptor.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <os/lock.h>


static const NSInteger kARStickerMenuItemTag = 0x41525345;
static const NSInteger kARStickerSeparatorTag = 0x41525353;
static const NSUInteger kARStickerMaxDownload = 20 * 1024 * 1024;

static NSError *ar_sticker_error(NSInteger code, NSString *message) {
    return [NSError errorWithDomain:@"local.WeChatIntercept.StickerExport" code:code
        userInfo:@{NSLocalizedDescriptionKey: message ?: @"未知错误"}];
}

@interface ARStickerPayload : NSObject
@property(copy) NSString *identifier;
@property(copy) NSArray<NSURL *> *plainURLs;
@property(strong) NSURL *encryptedURL;
@property(copy) NSData *aesKey;
@end
@implementation ARStickerPayload
@end

@interface ARStickerXML : NSObject <NSXMLParserDelegate>
@property(copy) NSDictionary<NSString *, NSString *> *attributes;
@property NSUInteger depth;
@property BOOL invalid;
@end

@implementation ARStickerXML
- (void)parser:(NSXMLParser *)parser didStartElement:(NSString *)name
  namespaceURI:(NSString *)uri qualifiedName:(NSString *)qualified
    attributes:(NSDictionary<NSString *, NSString *> *)attributes {
    _depth++;
    if (_depth > 10 || attributes.count > 64) {
        _invalid = YES;
        [parser abortParsing];
        return;
    }
    if (_depth == 1 && ![name isEqualToString:@"msg"]) {
        _invalid = YES;
        [parser abortParsing];
        return;
    }
    if ([name isEqualToString:@"emoji"]) {
        if (_depth != 2 || _attributes) {
            _invalid = YES;
            [parser abortParsing];
            return;
        }
        for (NSString *value in attributes.allValues) {
            if (![value isKindOfClass:NSString.class] || value.length > 8192) {
                _invalid = YES;
                [parser abortParsing];
                return;
            }
        }
        NSMutableDictionary *normalized = [NSMutableDictionary dictionary];
        [attributes enumerateKeysAndObjectsUsingBlock:
            ^(NSString *key, NSString *value, BOOL *stop) {
                normalized[key.lowercaseString] = value;
            }];
        _attributes = normalized;
    }
}
- (void)parser:(NSXMLParser *)parser didEndElement:(NSString *)name
  namespaceURI:(NSString *)uri qualifiedName:(NSString *)qualified {
    if (_depth) _depth--;
}
@end

static BOOL ar_sticker_hex(NSString *value, NSUInteger length) {
    if (![value isKindOfClass:NSString.class] || value.length != length) return NO;
    NSCharacterSet *invalid = [[NSCharacterSet characterSetWithCharactersInString:
        @"0123456789abcdefABCDEF"] invertedSet];
    return [value rangeOfCharacterFromSet:invalid].location == NSNotFound;
}

static NSData *ar_sticker_hex_data(NSString *value) {
    if (!ar_sticker_hex(value, 32)) return nil;
    uint8_t bytes[16];
    for (NSUInteger i = 0; i < sizeof(bytes); i++) {
        unsigned int byte = 0;
        NSString *pair = [value substringWithRange:NSMakeRange(i * 2, 2)];
        NSScanner *scanner = [NSScanner scannerWithString:pair];
        if (![scanner scanHexInt:&byte] || !scanner.isAtEnd) return nil;
        bytes[i] = (uint8_t)byte;
    }
    return [NSData dataWithBytes:bytes length:sizeof(bytes)];
}

static BOOL ar_sticker_host_allowed(NSString *host) {
    NSString *value = host.lowercaseString;
    if (!value.length || [value hasSuffix:@"."] || [value containsString:@":"]) return NO;
    NSArray<NSString *> *roots = @[@"qq.com", @"qpic.cn", @"weixin.qq.com", @"wechat.com"];
    for (NSString *root in roots) {
        if ([value isEqualToString:root] ||
            [value hasSuffix:[@"." stringByAppendingString:root]]) return YES;
    }
    return NO;
}

static NSURL *ar_sticker_safe_url(NSString *raw) {
    if (![raw isKindOfClass:NSString.class]) return nil;
    NSString *value = [raw stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (!value.length || value.length > 8192) return nil;
    if ([value hasPrefix:@"//"]) value = [@"https:" stringByAppendingString:value];
    NSURLComponents *parts = [NSURLComponents componentsWithString:value];
    NSString *scheme = parts.scheme.lowercaseString;
    if (![scheme isEqualToString:@"https"] && ![scheme isEqualToString:@"http"]) return nil;
    if (!ar_sticker_host_allowed(parts.host) || parts.user.length || parts.password.length) return nil;
    if (parts.port && parts.port.integerValue != 80 && parts.port.integerValue != 443) return nil;
    // Older emoticon records contain HTTP URLs. NSURLSession in WeChat rejects
    // them with NSURLErrorAppTransportSecurityRequiresSecureConnection (-1022).
    // Use the CDN's HTTPS endpoint, including for encrypted URLs and redirects.
    parts.scheme = @"https";
    parts.port = nil;
    parts.fragment = nil;
    return parts.URL;
}

static NSArray<NSURL *> *ar_sticker_url_candidates(NSURL *url) {
    if (!url) return @[];
    NSMutableArray<NSURL *> *result = [NSMutableArray arrayWithObject:url];
    NSString *host = url.host.lowercaseString;
    if ([host isEqualToString:@"vweixinf.tc.qq.com"] &&
        [url.path.lowercaseString containsString:@"/stodownload"]) {
        NSURLComponents *parts = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
        parts.host = @"wxapp.tc.qq.com";
        if (parts.URL) [result addObject:parts.URL];
    }
    return result;
}

static ARStickerPayload *ar_sticker_payload_from_attributes(
    NSDictionary<NSString *, NSString *> *attributes) {
    NSString *md5 = attributes[@"md5"].lowercaseString;
    if (!ar_sticker_hex(md5, 32)) return nil;

    NSMutableArray<NSURL *> *plain = [NSMutableArray array];
    NSMutableSet<NSString *> *seen = [NSMutableSet set];
    for (NSString *key in @[@"cdnurl", @"tpurl", @"externurl", @"url"]) {
        NSURL *url = ar_sticker_safe_url(attributes[key]);
        for (NSURL *candidate in ar_sticker_url_candidates(url)) {
            if (![seen containsObject:candidate.absoluteString]) {
                [seen addObject:candidate.absoluteString];
                [plain addObject:candidate];
            }
        }
    }

    NSURL *encrypted = ar_sticker_safe_url(attributes[@"encrypturl"]);
    NSData *aesKey = ar_sticker_hex_data(attributes[@"aeskey"]);

    ARStickerPayload *payload = [ARStickerPayload new];
    payload.identifier = md5;
    payload.plainURLs = plain;
    payload.encryptedURL = encrypted;
    payload.aesKey = aesKey;
    return payload;
}

static ARStickerPayload *ar_sticker_payload_from_xml(NSString *content) {
    if (![content isKindOfClass:NSString.class] || !content.length ||
        [content lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 65535 ||
        [content rangeOfString:@"<!DOCTYPE" options:NSCaseInsensitiveSearch].location != NSNotFound ||
        [content rangeOfString:@"<!ENTITY" options:NSCaseInsensitiveSearch].location != NSNotFound)
        return nil;

    NSRange start = [content rangeOfString:@"<msg"];
    BOOL wrapped = NO;
    if (start.location == NSNotFound) {
        start = [content rangeOfString:@"<emoji"];
        wrapped = start.location != NSNotFound;
    }
    if (start.location == NSNotFound) return nil;
    NSString *xml = [content substringFromIndex:start.location];
    if (wrapped) xml = [NSString stringWithFormat:@"<msg>%@</msg>", xml];

    ARStickerXML *delegate = [ARStickerXML new];
    NSXMLParser *parser = [[NSXMLParser alloc] initWithData:
        [xml dataUsingEncoding:NSUTF8StringEncoding]];
    parser.shouldResolveExternalEntities = NO;
    parser.delegate = delegate;
    if (![parser parse] || delegate.invalid || !delegate.attributes) return nil;
    return ar_sticker_payload_from_attributes(delegate.attributes);
}

// These opaque handles belong to the SQLite engine statically linked into
// wechat.dylib. System libsqlite3 functions MUST NOT receive these handles.
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
enum { AR_SQLITE_OK = 0, AR_SQLITE_ROW = 100, AR_SQLITE_DONE = 101 };

static int (*gARSQLiteExec)(sqlite3 *, const char *,
    int (*)(void *, int, char **, char **), void *, char **);
static const char *(*gARSQLiteDBFilename)(sqlite3 *, const char *);
static os_unfair_lock gARStickerMetadataLock = OS_UNFAIR_LOCK_INIT;
static NSDictionary<NSString *, ARStickerPayload *> *gARStickerMetadata;
static BOOL gARStickerMetadataLoading;
static NSUInteger gARStickerMetadataAttempts;
static __thread BOOL gARStickerInsideMetadataQuery;

static BOOL ar_sticker_emoticon_db_path(const char *path) {
    if (!path) return NO;
    size_t length = strnlen(path, 4097);
    const char *suffix = "/emoticon.db";
    size_t suffixLength = strlen(suffix);
    return length <= 4096 && length >= suffixLength &&
        !memcmp(path + length - suffixLength, suffix, suffixLength);
}

static int ar_sticker_metadata_row(void *context, int count,
                                   char **values, char **names) {
    (void)names;
    if (count != 6 || !values) return 1;
    NSMutableDictionary *loaded = (__bridge NSMutableDictionary *)context;
    if (loaded.count >= 20000) return 1;
    NSArray *keys = @[@"md5", @"aeskey", @"tpurl", @"cdnurl", @"externurl", @"encrypturl"];
    NSMutableDictionary *attributes = [NSMutableDictionary dictionary];
    for (int column = 0; column < count; column++) {
        const char *value = values[column];
        size_t length = value ? strnlen(value, 8193) : 0;
        if (!length || length > 8192) continue;
        NSString *text = [[NSString alloc] initWithBytes:value length:length
                                              encoding:NSUTF8StringEncoding];
        if (text) attributes[keys[column]] = text;
    }
    ARStickerPayload *payload = ar_sticker_payload_from_attributes(attributes);
    if (payload && (payload.plainURLs.count ||
        (payload.encryptedURL && payload.aesKey.length == 16)))
        loaded[payload.identifier] = payload;
    return 0;
}

// Run only on the caller's database thread, while its live statement still
// owns the connection. Never retain database pointers or query chat tables.
static BOOL ar_sticker_try_load_metadata(sqlite3 *database) {
    if (!database || gARStickerInsideMetadataQuery ||
        !gARSQLiteExec || !gARSQLiteDBFilename) return NO;
    const char *path = gARSQLiteDBFilename(database, "main");
    if (!ar_sticker_emoticon_db_path(path)) return NO;

    os_unfair_lock_lock(&gARStickerMetadataLock);
    if (gARStickerMetadataLoading) {
        os_unfair_lock_unlock(&gARStickerMetadataLock);
        return NO;
    }
    gARStickerMetadataLoading = YES;
    NSUInteger attempt = ++gARStickerMetadataAttempts;
    os_unfair_lock_unlock(&gARStickerMetadataLock);

    gARStickerInsideMetadataQuery = YES;
    NSMutableDictionary *loaded = [NSMutableDictionary dictionary];
    int status = gARSQLiteExec(database,
        "SELECT md5,aes_key,tp_url,cdn_url,extern_url,encrypt_url "
        "FROM kNonStoreEmoticonTable", ar_sticker_metadata_row,
        (__bridge void *)loaded, NULL);
    gARStickerInsideMetadataQuery = NO;

    os_unfair_lock_lock(&gARStickerMetadataLock);
    BOOL first = gARStickerMetadata == nil;
    if (status == AR_SQLITE_OK) gARStickerMetadata = [loaded copy];
    gARStickerMetadataLoading = NO;
    os_unfair_lock_unlock(&gARStickerMetadataLock);
    if (status == AR_SQLITE_OK && first)
        ARLOG("STICKER_METADATA_READY rows=%lu", (unsigned long)loaded.count);
    else if (status != AR_SQLITE_OK && attempt <= 3)
        ARLOG("STICKER_METADATA_QUERY_FAILED status=%d", status);
    return YES;
}

static ARStickerPayload *ar_sticker_enrich_payload(ARStickerPayload *payload) {
    if (!payload.identifier.length) return payload;
    os_unfair_lock_lock(&gARStickerMetadataLock);
    ARStickerPayload *metadata = gARStickerMetadata[payload.identifier];
    os_unfair_lock_unlock(&gARStickerMetadataLock);
    if (!metadata) return payload;

    ARStickerPayload *result = [ARStickerPayload new];
    result.identifier = payload.identifier;
    NSMutableOrderedSet<NSURL *> *urls = [NSMutableOrderedSet orderedSet];
    [urls addObjectsFromArray:payload.plainURLs ?: @[]];
    [urls addObjectsFromArray:metadata.plainURLs ?: @[]];
    result.plainURLs = urls.array;
    // A URL and its key must come from the same record.
    ARStickerPayload *encryptedSource = payload.encryptedURL && payload.aesKey.length == 16
        ? payload : metadata;
    result.encryptedURL = encryptedSource.encryptedURL;
    result.aesKey = encryptedSource.aesKey;
    return result;
}

#if !defined(WECHATINTERCEPT_TEST) && defined(__arm64__)
static uintptr_t gARStickerSQLiteStepContinue __attribute__((used));
static const char *(*gARSQLiteSQL)(sqlite3_stmt *);
static void (*gARSQLiteError)(sqlite3 *, int);
static void (*gARSQLiteMutexEnter)(void *);
static void (*gARSQLiteMutexLeave)(void *);

__attribute__((naked, noinline))
static int ar_sticker_sqlite_step_original(sqlite3_stmt *statement) {
    __asm__ volatile(
        "adrp x16, _gARStickerSQLiteStepContinue@PAGE\n"
        "ldr x16, [x16, _gARStickerSQLiteStepContinue@PAGEOFF]\n"
        "stp x28, x27, [sp, #-0x60]!\n"
        "stp x26, x25, [sp, #0x10]\n"
        "stp x24, x23, [sp, #0x20]\n"
        "stp x22, x21, [sp, #0x30]\n"
        "br x16\n");
}

static int ar_sticker_sqlite_step(sqlite3_stmt *statement) {
    int status = ar_sticker_sqlite_step_original(statement);
    if (status != AR_SQLITE_DONE || gARStickerInsideMetadataQuery) return status;
    const char *sql = gARSQLiteSQL(statement);
    // Wait for an actual emoticon-table statement to finish. In particular,
    // do not re-enter SQLite while it is initializing a database schema.
    if (!sql || !strstr(sql, "kNonStoreEmoticonTable")) return status;
    @autoreleasepool {
        sqlite3 *database = NULL;
        void *mutex = NULL;
        memcpy(&database, statement, sizeof(database));
        memcpy(&mutex, (uint8_t *)database + 0x18, sizeof(mutex));
        gARSQLiteMutexEnter(mutex);
        if (ar_sticker_try_load_metadata(database))
            gARSQLiteError(database, status);
        gARSQLiteMutexLeave(mutex);
    }
    return status;
}

static BOOL ar_sticker_database_start(const struct mach_header *header, uintptr_t slide) {
    if (!ar_marker_supported_core(header) || !slide) return NO;
    // WeChat 4.1.13 arm64 / SQLite 3.27.2. Verify code in addition to UUID.
    const struct { uintptr_t offset; uint32_t code[4]; } checks[] = {
        {0x5570764, {0xa9ba6ffc, 0xa90167fa, 0xa9025ff8, 0xa90357f6}},
        {0x552ad90, {0xd10203ff, 0xa9026ffc, 0xa90367fa, 0xa9045ff8}},
        {0x55322e0, {0xd10103ff, 0xa9024ff4, 0xa9037bfd, 0x9100c3fd}},
        {0x55670c0, {0xb9005001, 0x35000061, 0xf940bc08, 0xb4000048}},
    };
    for (NSUInteger i = 0; i < sizeof(checks) / sizeof(checks[0]); i++) {
        uint32_t actual[4];
        if (!read_bytes(slide + checks[i].offset, actual, sizeof(actual)) ||
            memcmp(actual, checks[i].code, sizeof(actual))) return NO;
    }
    const uint32_t sqlCode[] = {0xb4000040, 0xf9407c00, 0xd65f03c0};
    uint32_t actualSQL[3], dbLoad = 0, fifth = 0;
    if (!read_bytes(slide + 0x5571d28, actualSQL, sizeof(actualSQL)) ||
        memcmp(actualSQL, sqlCode, sizeof(sqlCode)) ||
        !read_bytes(slide + 0x5570788, &dbLoad, sizeof(dbLoad)) || dbLoad != 0xf9400013 ||
        !read_bytes(slide + 0x5570774, &fifth, sizeof(fifth)) || fifth != 0xa9044ff4)
        return NO;

    gARSQLiteExec = (void *)(slide + 0x552ad90);
    gARSQLiteDBFilename = (void *)(slide + 0x55322e0);
    gARSQLiteError = (void *)(slide + 0x55670c0);
    gARSQLiteSQL = (void *)(slide + 0x5571d28);
    gARSQLiteMutexEnter = (void *)(slide + 0x5534120);
    gARSQLiteMutexLeave = (void *)(slide + 0x5534138);
    gARStickerSQLiteStepContinue = slide + 0x5570774;
    if (!install_arm64_trampoline(slide + 0x5570764, (uintptr_t)ar_sticker_sqlite_step))
        return NO;
    ARLOG("STICKER_METADATA_HOOK_READY backend=wechat-sqlite");
    return YES;
}
#endif

@interface ARStickerImage : NSObject
@property(copy) NSData *data;
@property(copy) NSString *extension;
@end
@implementation ARStickerImage
@end

static BOOL ar_sticker_gif_blocks(const uint8_t *bytes, NSUInteger length, NSUInteger *pos) {
    while (*pos < length) {
        NSUInteger size = bytes[(*pos)++];
        if (!size) return YES;
        if (size > length - *pos) return NO;
        *pos += size;
    }
    return NO;
}

static NSUInteger ar_sticker_gif_end(const uint8_t *bytes, NSUInteger start, NSUInteger length) {
    if (length - start < 13) return 0;
    uint8_t packed = bytes[start + 10];
    NSUInteger pos = start + 13 + ((packed & 0x80) ? 3u << ((packed & 7) + 1) : 0);
    BOOL hasFrame = NO;
    while (pos < length) {
        uint8_t marker = bytes[pos++];
        if (marker == 0x3b) return hasFrame ? pos : 0;
        if (marker == 0x21) {
            if (pos >= length) return 0;
            pos++; // Extension label; its payload uses length-prefixed blocks.
        } else if (marker == 0x2c) {
            if (length - pos < 9) return 0;
            packed = bytes[pos + 8];
            pos += 9 + ((packed & 0x80) ? 3u << ((packed & 7) + 1) : 0);
            if (pos >= length) return 0;
            pos++; // LZW minimum code size.
            hasFrame = YES;
        } else return 0;
        if (!ar_sticker_gif_blocks(bytes, length, &pos)) return 0;
    }
    return 0;
}

static BOOL ar_sticker_image_complete(NSData *data) {
    CGImageSourceRef source = CGImageSourceCreateWithData((__bridge CFDataRef)data,
        (__bridge CFDictionaryRef)@{(id)kCGImageSourceShouldCache: @NO});
    if (!source) return NO;
    BOOL valid = CGImageSourceGetCount(source) > 0 &&
        CGImageSourceGetStatus(source) == kCGImageStatusComplete;
    NSDictionary *properties = valid ? CFBridgingRelease(
        CGImageSourceCopyPropertiesAtIndex(source, 0, NULL)) : nil;
    uint64_t width = [properties[(id)kCGImagePropertyPixelWidth] unsignedLongLongValue];
    uint64_t height = [properties[(id)kCGImagePropertyPixelHeight] unsignedLongLongValue];
    valid = valid && width > 0 && height > 0 && width <= 32768 &&
        height <= 32768 && width * height <= 32 * 1024 * 1024;
    CGImageRef frame = valid ? CGImageSourceCreateImageAtIndex(source, 0, NULL) : NULL;
    valid = frame && CGImageSourceGetStatusAtIndex(source, 0) == kCGImageStatusComplete;
    if (frame) CGImageRelease(frame);
    CFRelease(source);
    return valid;
}

static ARStickerImage *ar_sticker_image(NSData *source) {
    if (![source isKindOfClass:NSData.class] || source.length < 6 ||
        source.length > kARStickerMaxDownload) return nil;
    const uint8_t *bytes = source.bytes;
    NSUInteger length = source.length;
    NSUInteger scanLimit = MIN(length, 1024 * 1024);

    for (NSUInteger start = 0; start < scanLimit; start++) {
        NSUInteger end = 0;
        NSString *extension = nil;
        if (start + 6 <= length &&
            (!memcmp(bytes + start, "GIF87a", 6) || !memcmp(bytes + start, "GIF89a", 6))) {
            end = ar_sticker_gif_end(bytes, start, length);
            if (end) extension = @"gif";
        } else if (start + 8 <= length &&
                   !memcmp(bytes + start, "\x89PNG\r\n\x1a\n", 8)) {
            NSUInteger pos = start + 8;
            while (pos + 12 <= length) {
                uint32_t chunk = ((uint32_t)bytes[pos] << 24) |
                                 ((uint32_t)bytes[pos + 1] << 16) |
                                 ((uint32_t)bytes[pos + 2] << 8) | bytes[pos + 3];
                if ((NSUInteger)chunk > length - pos - 12) break;
                BOOL iend = !memcmp(bytes + pos + 4, "IEND", 4);
                pos += 12 + (NSUInteger)chunk;
                if (iend) { end = pos; break; }
            }
            if (end) extension = @"png";
        } else if (start + 12 <= length && !memcmp(bytes + start, "RIFF", 4) &&
                   !memcmp(bytes + start + 8, "WEBP", 4)) {
            uint32_t size = (uint32_t)bytes[start + 4] |
                            ((uint32_t)bytes[start + 5] << 8) |
                            ((uint32_t)bytes[start + 6] << 16) |
                            ((uint32_t)bytes[start + 7] << 24);
            uint64_t candidate = (uint64_t)start + 8 + size;
            if (candidate <= length) { end = (NSUInteger)candidate; extension = @"webp"; }
        } else if (start + 3 <= length && bytes[start] == 0xff &&
                   bytes[start + 1] == 0xd8 && bytes[start + 2] == 0xff) {
            for (NSUInteger pos = start + 3; pos + 1 < length; pos++) {
                if (bytes[pos] == 0xff && bytes[pos + 1] == 0xd9) {
                    end = pos + 2;
                    extension = @"jpg";
                    break;
                }
            }
        }
        if (extension && end > start) {
            NSData *data = [source subdataWithRange:NSMakeRange(start, end - start)];
            // Ciphertext and truncated files can contain image signatures by
            // chance. Decode for validation, but save the original bytes so
            // animated GIF/WebP frames are not flattened or recompressed.
            if (!ar_sticker_image_complete(data)) continue;
            ARStickerImage *image = [ARStickerImage new];
            image.data = data;
            image.extension = extension;
            return image;
        }
    }
    return nil;
}

static NSData *ar_sticker_decrypt(NSData *encrypted, NSData *key) {
    if (key.length != kCCKeySizeAES128 || !encrypted.length ||
        encrypted.length % kCCBlockSizeAES128 != 0 ||
        encrypted.length > kARStickerMaxDownload) return nil;
    NSMutableData *output = [NSMutableData dataWithLength:encrypted.length + kCCBlockSizeAES128];
    size_t written = 0;
    CCCryptorStatus status = CCCrypt(kCCDecrypt, kCCAlgorithmAES, 0,
        key.bytes, key.length, key.bytes, encrypted.bytes, encrypted.length,
        output.mutableBytes, output.length, &written);
    if (status != kCCSuccess || written != encrypted.length) return nil;
    output.length = written;
    return output;
}

static NSData *ar_sticker_aes_decrypt(NSData *encrypted, NSData *key,
                                      const void *iv, CCOptions options) {
    if (key.length != kCCKeySizeAES128 || !encrypted.length ||
        encrypted.length % kCCBlockSizeAES128 != 0 ||
        encrypted.length > kARStickerMaxDownload) return nil;
    NSMutableData *output = [NSMutableData dataWithLength:
        encrypted.length + kCCBlockSizeAES128];
    size_t written = 0;
    CCCryptorStatus status = CCCrypt(kCCDecrypt, kCCAlgorithmAES, options,
        key.bytes, key.length, iv, encrypted.bytes, encrypted.length,
        output.mutableBytes, output.length, &written);
    if (status != kCCSuccess || !written || written > output.length) return nil;
    output.length = written;
    return output;
}

static ARStickerImage *ar_sticker_try_aes_image(NSData *encrypted, NSData *key,
                                                 const void *iv, CCOptions options) {
    NSData *decrypted = ar_sticker_aes_decrypt(encrypted, key, iv, options);
    return decrypted ? ar_sticker_image(decrypted) : nil;
}

static ARStickerImage *ar_sticker_decrypt_image(NSData *encrypted, NSData *key) {
    if (key.length != 16 || encrypted.length < 16 ||
        encrypted.length > kARStickerMaxDownload) return nil;
    // Current ef=2 resources prefix a random 16-byte CBC IV.
    if (encrypted.length > 16 && (encrypted.length - 16) % 16 == 0) {
        NSData *body = [encrypted subdataWithRange:
            NSMakeRange(16, encrypted.length - 16)];
        const CCOptions options[] = {kCCOptionPKCS7Padding, 0};
        for (NSUInteger index = 0; index < sizeof(options) / sizeof(options[0]); index++) {
            ARStickerImage *image = ar_sticker_try_aes_image(body, key,
                encrypted.bytes, options[index]);
            if (image) return image;
        }
    }

    // Older resources use the key itself as CBC IV. Keep ECB as a narrow
    // compatibility fallback; every candidate still has to pass image-magic
    // and structural validation before it can be saved.
    if (encrypted.length % 16 == 0) {
        const CCOptions paddings[] = {kCCOptionPKCS7Padding, 0};
        for (NSUInteger index = 0; index < sizeof(paddings) / sizeof(paddings[0]); index++) {
            CCOptions padding = paddings[index];
            ARStickerImage *image = ar_sticker_try_aes_image(
                encrypted, key, key.bytes, padding);
            if (image) return image;
            image = ar_sticker_try_aes_image(encrypted, key, NULL,
                kCCOptionECBMode | padding);
            if (image) return image;
        }
    }
    return nil;
}

typedef void (^ARStickerDownloadCompletion)(NSData *data, NSError *error);

@interface ARStickerDownload : NSObject <NSURLSessionDataDelegate, NSURLSessionTaskDelegate>
@property(strong) NSURLSession *session;
@property(strong) NSMutableData *data;
@property(copy) ARStickerDownloadCompletion completion;
@property(strong) NSError *responseError;
@property NSUInteger redirects;
- (void)start:(NSURL *)url completion:(ARStickerDownloadCompletion)completion;
@end

@implementation ARStickerDownload
- (void)start:(NSURL *)url completion:(ARStickerDownloadCompletion)completion {
    _completion = completion;
    _data = [NSMutableData data];
    NSURLSessionConfiguration *config = NSURLSessionConfiguration.ephemeralSessionConfiguration;
    config.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    config.timeoutIntervalForRequest = 20;
    config.timeoutIntervalForResource = 30;
    _session = [NSURLSession sessionWithConfiguration:config delegate:self delegateQueue:nil];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    [request setValue:@"image/*" forHTTPHeaderField:@"Accept"];
    [[_session dataTaskWithRequest:request] resume];
}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
  willPerformHTTPRedirection:(NSHTTPURLResponse *)response
          newRequest:(NSURLRequest *)request
   completionHandler:(void (^)(NSURLRequest *))completionHandler {
    NSURL *safe = ar_sticker_safe_url(request.URL.absoluteString);
    if (safe && _redirects++ < 3) {
        NSMutableURLRequest *redirect = [request mutableCopy];
        redirect.URL = safe;
        completionHandler(redirect);
    } else {
        _responseError = ar_sticker_error(21, @"下载地址跳转不安全");
        completionHandler(nil);
    }
}
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)task
 didReceiveResponse:(NSURLResponse *)response
  completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    NSInteger status = [response isKindOfClass:NSHTTPURLResponse.class]
        ? ((NSHTTPURLResponse *)response).statusCode : 0;
    BOOL lengthOK = response.expectedContentLength < 0 ||
        (uint64_t)response.expectedContentLength <= kARStickerMaxDownload;
    if (status < 200 || status >= 300 || !lengthOK ||
        !ar_sticker_safe_url(response.URL.absoluteString)) {
        ARLOG("STICKER_DOWNLOAD_REJECTED status=%ld expected_bytes=%lld",
              (long)status, response.expectedContentLength);
        _responseError = !lengthOK ? ar_sticker_error(23, @"表情文件超过 20 MB")
            : ar_sticker_error(22, [NSString stringWithFormat:
                @"表情服务器返回无效响应（HTTP %ld），请稍后重试。", (long)status]);
        completionHandler(NSURLSessionResponseCancel);
        return;
    }
    completionHandler(NSURLSessionResponseAllow);
}
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)task
    didReceiveData:(NSData *)data {
    if (_data.length + data.length > kARStickerMaxDownload) {
        _responseError = ar_sticker_error(23, @"表情文件超过 20 MB");
        [task cancel];
    } else [_data appendData:data];
}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
 didCompleteWithError:(NSError *)error {
    ARStickerDownloadCompletion completion = _completion;
    _completion = nil;
    NSData *data = (!_responseError && !error) ? [_data copy] : nil;
    NSError *resultError = _responseError ?: error;
    [_session finishTasksAndInvalidate];
    _session = nil;
    _data = nil;
    if (completion) completion(data, resultError);
}
@end

static void ar_sticker_download(NSURL *url, ARStickerDownloadCompletion completion) {
    ARStickerDownload *download = [ARStickerDownload new];
    [download start:url completion:completion];
}

typedef void (^ARStickerFetchCompletion)(ARStickerImage *image, NSError *error);

@interface ARStickerFetchJob : NSObject
@property(strong) ARStickerPayload *payload;
@property NSUInteger index;
@property NSUInteger encryptedIndex;
@property(strong) NSError *lastError;
@property(copy) ARStickerFetchCompletion completion;
- (void)start;
@end

@implementation ARStickerFetchJob
- (void)finish:(ARStickerImage *)image error:(NSError *)error {
    ARStickerFetchCompletion completion = _completion;
    _completion = nil;
    if (completion) completion(image, error);
}
- (void)start {
    _payload = ar_sticker_enrich_payload(_payload);
    ARLOG("STICKER_FETCH_READY plain=%lu encrypted=%d key=%d",
          (unsigned long)_payload.plainURLs.count, _payload.encryptedURL != nil,
          _payload.aesKey.length == 16);
    [self tryNext];
}
- (void)tryNext {
    NSURL *url = nil;
    BOOL encrypted = NO;
    NSArray<NSURL *> *encryptedURLs = ar_sticker_url_candidates(_payload.encryptedURL);
    if (_index < _payload.plainURLs.count) {
        url = _payload.plainURLs[_index++];
    } else if (_encryptedIndex < encryptedURLs.count && _payload.aesKey.length == 16) {
        encrypted = YES;
        url = encryptedURLs[_encryptedIndex++];
    }
    if (!url) {
        [self finish:nil error:_lastError ?: ar_sticker_error(30,
            @"尚未取得这个表情的原图地址，请重新打开聊天后再试。")];
        return;
    }
    ar_sticker_download(url, ^(NSData *data, NSError *error) {
        ARStickerImage *image = data ? ar_sticker_image(data) : nil;
        if (!image && data && (encrypted || self.payload.aesKey.length == 16))
            image = ar_sticker_decrypt_image(data, self.payload.aesKey);
        if (image) {
            ARLOG("STICKER_FETCH_SUCCEEDED format=%s bytes=%lu",
                  image.extension.UTF8String, (unsigned long)image.data.length);
            [self finish:image error:nil];
        }
        else {
            if ([error.domain isEqualToString:@"local.WeChatIntercept.StickerExport"])
                self.lastError = error;
            else if (error)
                self.lastError = ar_sticker_error(31, [NSString stringWithFormat:
                    @"表情原图下载失败（网络错误 %ld），请稍后重试。", (long)error.code]);
            else self.lastError = ar_sticker_error(32,
                @"已下载数据，但未能解码原始表情图片。");
            ARLOG("STICKER_FETCH_FAILED stage=%s code=%ld bytes=%lu",
                  error ? "download" : "decode", (long)error.code,
                  (unsigned long)data.length);
            [self tryNext];
        }
    });
}
@end

static const uint8_t *ar_sticker_find_bytes(const uint8_t *bytes, size_t length,
                                            const char *needle, size_t needleLength) {
    if (!bytes || !needleLength || length < needleLength) return NULL;
    for (size_t offset = 0; offset + needleLength <= length; offset++)
        if (!memcmp(bytes + offset, needle, needleLength)) return bytes + offset;
    return NULL;
}

static NSString *ar_sticker_xml_in_buffer(const uint8_t *bytes, size_t length) {
    const uint8_t *emoji = ar_sticker_find_bytes(bytes, length, "<emoji", 6);
    if (!emoji) return nil;
    const uint8_t *start = NULL;
    for (const uint8_t *cursor = bytes; cursor + 4 <= emoji; cursor++)
        if (!memcmp(cursor, "<msg", 4)) start = cursor;
    if (!start) return nil;
    size_t remaining = length - (size_t)(emoji - bytes);
    const uint8_t *end = ar_sticker_find_bytes(emoji, remaining, "</msg>", 6);
    if (!end) return nil;
    size_t xmlLength = (size_t)(end + 6 - start);
    if (!xmlLength || xmlLength > 65535) return nil;
    return [[NSString alloc] initWithBytes:start length:xmlLength
                                  encoding:NSUTF8StringEncoding];
}

static ARStickerPayload *ar_sticker_payload_for_view(uintptr_t view) {
    if (!gARMarkerReady || !gARMessageInfoTable ||
        !ar_qt_inherits(view, @"mmui::ChatItemView")) return nil;
    uintptr_t model = ar_pointer(view + 0x230);
    if (!model || ar_pointer(model + 0x120) != gARMessageInfoTable) return nil;

    // MessageInfo is embedded at model + 0x120. Its +0x8 field is the message
    // type; 47 is WeChat's custom/animated emoticon. In 4.1.13 the type-47
    // payload owner is MessageInfo + 0x238 and its XML is the alternate-layout
    // libc++ string at owner + 0x130. This path was validated against the live
    // row that builds the sticker context menu.
    uint32_t messageType = 0;
    if (!read_bytes(model + 0x128, &messageType, sizeof(messageType)) ||
        messageType != 47) return nil;
    uintptr_t payloadObject = ar_pointer(model + 0x358);
    NSString *content = payloadObject
        ? ar_cpp_string(payloadObject + 0x130, 65535) : nil;

    // Keep the previously observed bounded layouts as narrow fallbacks for
    // recycled/quoted rows whose payload owner has not yet been populated.
    uint8_t inlineBytes[4096] = {0};
    if (!content && read_bytes(model, inlineBytes, sizeof(inlineBytes)))
        content = ar_sticker_xml_in_buffer(inlineBytes, sizeof(inlineBytes));

    uintptr_t contentObject = ar_pointer(model + 0x530);
    if (!content && contentObject) {
        uint8_t bytes[8192] = {0};
        if (read_bytes(contentObject, bytes, sizeof(bytes)))
            content = ar_sticker_xml_in_buffer(bytes, sizeof(bytes));
    }
    if (ar_pointer(view + 0x230) != model ||
        ar_pointer(model + 0x120) != gARMessageInfoTable) return nil;
    uint32_t verifiedType = 0;
    if (!read_bytes(model + 0x128, &verifiedType, sizeof(verifiedType)) ||
        verifiedType != messageType ||
        (payloadObject && ar_pointer(model + 0x358) != payloadObject)) return nil;
    if (contentObject && ar_pointer(model + 0x530) != contentObject) return nil;
    return ar_sticker_payload_from_xml(content);
}

static NSView *ar_sticker_qns_host(NSView *view, NSEvent *event) {
    Class qnsClass = NSClassFromString(@"QNSView");
    for (NSView *candidate = view; candidate; candidate = candidate.superview)
        if ([candidate isKindOfClass:qnsClass]) return candidate;

    for (NSWindow *window in @[view.window ?: NSNull.null,
                               event.window ?: NSNull.null,
                               NSApp.keyWindow ?: NSNull.null,
                               NSApp.mainWindow ?: NSNull.null]) {
        if (![window isKindOfClass:NSWindow.class]) continue;
        NSView *content = window.contentView;
        if ([content isKindOfClass:qnsClass] && ar_root_for_host(content))
            return content;
    }
    for (NSWindow *window in NSApp.windows) {
        NSView *content = window.contentView;
        if ([content isKindOfClass:qnsClass] && ar_root_for_host(content))
            return content;
    }
    return nil;
}

static ARStickerPayload *ar_sticker_payload_at_event(NSEvent *event, NSView *view) {
    if (!event) {
        ARLOG("STICKER_MENU_SCAN host=no rows=0 point_hits=0 bubble_hits=0 payload_hits=0");
        return nil;
    }
    NSView *host = ar_sticker_qns_host(view, event);
    uintptr_t root = ar_root_for_host(host);
    if (!host || !root) {
        ARLOG("STICKER_MENU_SCAN host=no rows=0 point_hits=0 bubble_hits=0 payload_hits=0");
        return nil;
    }
    NSPoint windowPoint = event.locationInWindow;
    if (event.window && host.window && event.window != host.window) {
        NSPoint screenPoint = [event.window convertPointToScreen:windowPoint];
        windowPoint = [host.window convertPointFromScreen:screenPoint];
    }
    NSPoint point = [host convertPoint:windowPoint fromView:nil];
    if (!host.isFlipped) point.y = NSHeight(host.bounds) - point.y;

    NSMutableArray<NSNumber *> *rows = [NSMutableArray array];
    ar_collect(root, @"mmui::ChatItemView", YES, rows,
        [NSMutableSet set], 0, 12000);
    ARStickerPayload *best = nil;
    CGFloat bestArea = CGFLOAT_MAX;
    NSUInteger pointHits = 0, bubbleHits = 0, payloadHits = 0;
    for (NSNumber *number in rows) {
        uintptr_t row = number.unsignedLongLongValue;
        NSRect rect;
        if (!ar_qt_global_rect(row, root, &rect) || !NSPointInRect(point, rect)) continue;
        pointHits++;
        NSRect bubble = ar_bubble_rect(row, root);
        if (!NSIsEmptyRect(bubble) && !NSPointInRect(point, NSInsetRect(bubble, -4, -4))) continue;
        bubbleHits++;
        ARStickerPayload *payload = ar_sticker_payload_for_view(row);
        CGFloat area = NSWidth(rect) * NSHeight(rect);
        if (payload) {
            payloadHits++;
            if (area < bestArea) { best = payload; bestArea = area; }
        }
    }
    ARLOG("STICKER_MENU_SCAN host=yes rows=%lu point_hits=%lu bubble_hits=%lu payload_hits=%lu",
          (unsigned long)rows.count, (unsigned long)pointHits,
          (unsigned long)bubbleHits, (unsigned long)payloadHits);
    return best;
}

@interface ARStickerExporter : NSObject
+ (instancetype)shared;
- (void)exportPayload:(ARStickerPayload *)payload;
- (void)exportSticker:(NSMenuItem *)sender;
@end

@implementation ARStickerExporter
+ (instancetype)shared {
    static ARStickerExporter *value;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ value = [ARStickerExporter new]; });
    return value;
}
- (void)showError:(NSString *)message {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSAlert *alert = [NSAlert new];
        alert.messageText = @"表情导出失败";
        alert.informativeText = message ?: @"无法读取原始表情数据";
        NSWindow *window = NSApp.keyWindow ?: NSApp.mainWindow;
        if (window) [alert beginSheetModalForWindow:window completionHandler:nil];
        else [alert runModal];
    });
}
- (void)saveImage:(ARStickerImage *)image payload:(ARStickerPayload *)payload {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSSavePanel *panel = NSSavePanel.savePanel;
        panel.nameFieldStringValue = [NSString stringWithFormat:@"%@.%@",
            payload.identifier, image.extension];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        panel.allowedFileTypes = @[image.extension];
#pragma clang diagnostic pop
        panel.allowsOtherFileTypes = NO;
        panel.extensionHidden = NO;
        panel.canCreateDirectories = YES;
        void (^complete)(NSModalResponse) = ^(NSModalResponse result) {
            if (result != NSModalResponseOK) return;
            NSError *error = nil;
            if (![image.data writeToURL:panel.URL options:NSDataWritingAtomic error:&error])
                [self showError:@"写入所选文件失败"];
            else ARLOG("STICKER_EXPORT_SAVED format=%s",
                       image.extension.UTF8String ?: "unknown");
        };
        NSWindow *window = NSApp.keyWindow ?: NSApp.mainWindow;
        if (window) [panel beginSheetModalForWindow:window completionHandler:complete];
        else [panel beginWithCompletionHandler:complete];
    });
}
- (void)exportPayload:(ARStickerPayload *)payload {
    if (!payload) return;
    ARLOG("STICKER_EXPORT_STARTED");
    ARStickerFetchJob *job = [ARStickerFetchJob new];
    job.payload = payload;
    job.completion = ^(ARStickerImage *image, NSError *error) {
        if (image) [self saveImage:image payload:payload];
        else {
            ARLOG("STICKER_EXPORT_FAILED code=%ld", (long)error.code);
            [self showError:error.localizedDescription];
        }
    };
    [job start];
}
- (void)exportSticker:(NSMenuItem *)sender {
    ARStickerPayload *payload = [sender.representedObject isKindOfClass:ARStickerPayload.class]
        ? sender.representedObject : nil;
    [self exportPayload:payload];
}
@end

static void ar_sticker_prepare_menu(NSMenu *menu, NSEvent *event, NSView *view) {
    if (!menu || !gARMarkerReady) return;
    for (NSMenuItem *item in [menu.itemArray copy]) {
        if (item.tag == kARStickerMenuItemTag || item.tag == kARStickerSeparatorTag)
            [menu removeItem:item];
    }
    ARStickerPayload *payload = ar_sticker_payload_at_event(event, view);
    if (!payload) return;
    NSMenuItem *separator = NSMenuItem.separatorItem;
    separator.tag = kARStickerSeparatorTag;
    [menu addItem:separator];
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:@"导出表情…"
        action:@selector(exportSticker:) keyEquivalent:@""];
    item.tag = kARStickerMenuItemTag;
    item.target = ARStickerExporter.shared;
    item.representedObject = payload;
    [menu addItem:item];
    ARLOG("STICKER_MENU_READY");
}

static BOOL ar_sticker_is_context_event(NSEvent *event) {
    if (!event) return NO;
    if (event.type == NSEventTypeRightMouseDown ||
        event.type == NSEventTypeRightMouseUp) return YES;
    return (event.type == NSEventTypeLeftMouseDown ||
            event.type == NSEventTypeLeftMouseUp) &&
           (event.modifierFlags & NSEventModifierFlagControl) != 0;
}

static BOOL ar_sticker_exchange(Method original, Method replacement);

// 微信 4.1.13 的聊天菜单是 Qt 自绘 XMenu，不经过 NSMenu。以下校验只接受
// `QMetaObject::activate(this, staticMetaObject, 0, nullptr)` 的五条指令包装器，
// 避免版本漂移时把未知函数覆盖掉。
static BOOL ar_sticker_qt_signal_shape(const uint32_t code[5]) {
    return code &&
        (code[0] & 0x9f00001f) == 0x90000001 && // ADRP X1, ...
        (code[1] & 0xffc003ff) == 0x91000021 && // ADD  X1, X1, ...
        code[2] == 0x52800002 &&                 // MOV  W2, #0
        code[3] == 0xd2800003 &&                 // MOV  X3, #0
        (code[4] & 0xfc000000) == 0x14000000;   // B    QMetaObject::activate
}

static uintptr_t ar_sticker_qt_adrp_add_target(uintptr_t address,
                                                uint32_t adrp, uint32_t add) {
    int64_t pages = (int64_t)((((adrp >> 5) & 0x7ffff) << 2) |
                              ((adrp >> 29) & 3));
    if (pages & (1 << 20)) pages -= 1 << 21;
    uintptr_t offset = (uintptr_t)((add >> 10) & 0xfff);
    if (add & (1u << 22)) offset <<= 12;
    return (address & ~(uintptr_t)0xfff) + (intptr_t)(pages * 4096) + offset;
}

static uintptr_t ar_sticker_qt_branch_target(uintptr_t address, uint32_t branch) {
    int64_t words = branch & 0x03ffffff;
    if (words & (1 << 25)) words -= 1 << 26;
    return address + (intptr_t)(words * 4);
}

static BOOL ar_sticker_qt_signal_wrapper(uintptr_t address,
                                          uintptr_t expectedMeta,
                                          uintptr_t expectedActivate) {
    uint32_t code[5];
    return read_bytes(address, code, sizeof(code)) &&
        ar_sticker_qt_signal_shape(code) &&
        ar_sticker_qt_adrp_add_target(address, code[0], code[1]) == expectedMeta &&
        ar_sticker_qt_branch_target(address + 16, code[4]) == expectedActivate;
}

#if !defined(WECHATINTERCEPT_TEST) && defined(__arm64__)

// UUID 918FFBFD-E18D-363F-B07C-B8D7F1436727 (WeChat 4.1.13 build 269631).
// 所有地址在安装前还会由上面的指令和 QMetaObject 布局二次校验。
enum {
    kARQtXMenuLayoutOffset     = 0x1d8ccfc,
    kARQtXViewClickedOffset     = 0x1d6157c,
    kARQtActivateOffset         = 0x6c34738,
    kARQtXMenuMetaOffset        = 0x98a5da0,
    kARQtXViewMetaOffset        = 0x98a6780,
    kARQtDefaultStyleOffset     = 0x98a56b8,
    kARQtUtf8StringOffset       = 0x6b52dac,
    kARQtStringReleaseOffset    = 0x0acd18,
    kARQtOperatorNewOffset      = 0x6d968c8,
    kARQtOperatorDeleteOffset   = 0x6d968a4,
    kARQtXMenuItemCtorOffset    = 0x1d90944,
    kARQtXMenuItemCtorImplOffset = 0x1d905d4,
    kARQtXMenuAddOffset         = 0x1d8ba7c,
};

static uintptr_t gARStickerQtSlide;
static void (*gARStickerQtActivate)(void *, const void *, int, void **);
static NSMutableDictionary<NSNumber *, NSDictionary *> *gARStickerQtItems;
static ARStickerPayload *gARStickerPendingPayload;
static NSTimeInterval gARStickerPendingAt;
static BOOL gARStickerQtReady;
static uintptr_t gARStickerQtLayoutContinue __attribute__((used));

static BOOL ar_sticker_qt_implementation_matches(uintptr_t slide) {
    uint32_t ctor = 0, layout[4] = {0}, add[5] = {0}, utf8[2] = {0};
    uint32_t release[6] = {0};
    return
        read_bytes(slide + kARQtXMenuItemCtorOffset, &ctor, sizeof(ctor)) &&
        (ctor & 0xfc000000) == 0x14000000 &&
        ar_sticker_qt_branch_target(slide + kARQtXMenuItemCtorOffset, ctor) ==
            slide + kARQtXMenuItemCtorImplOffset &&
        read_bytes(slide + kARQtXMenuLayoutOffset, layout, sizeof(layout)) &&
        layout[0] == 0xd10303ff && layout[1] == 0x6d0523e9 &&
        layout[2] == 0xa9066ffc && layout[3] == 0xa90767fa &&
        read_bytes(slide + kARQtXMenuAddOffset, add, sizeof(add)) &&
        add[0] == 0xd10143ff && add[1] == 0xa9015ff8 &&
        add[2] == 0xa90257f6 && add[3] == 0xa9034ff4 &&
        add[4] == 0xa9047bfd &&
        read_bytes(slide + kARQtUtf8StringOffset, utf8, sizeof(utf8)) &&
        utf8[0] == 0xb4000040 && (utf8[1] & 0xfc000000) == 0x14000000 &&
        read_bytes(slide + kARQtStringReleaseOffset, release, sizeof(release)) &&
        release[0] == 0xa9be4ff4 && release[1] == 0xa9017bfd &&
        release[2] == 0x910043fd && release[3] == 0xaa0003e8 &&
        release[4] == 0xf9400000 && release[5] == 0xb9400009;
}

// Replay only the four verified, position-independent prologue instructions.
// XMenu builds its XMenuView rows BEFORE its aboutToShow signal is emitted.
// Inserting at that signal adds a QAction but leaves the visible layout stale.
__attribute__((naked, noinline))
static void ar_sticker_qt_layout_original(void *object) {
    __asm__ volatile(
        "adrp x16, _gARStickerQtLayoutContinue@PAGE\n"
        "ldr x16, [x16, _gARStickerQtLayoutContinue@PAGEOFF]\n"
        "sub sp, sp, #0xc0\n"
        "stp d9, d8, [sp, #0x50]\n"
        "stp x28, x27, [sp, #0x60]\n"
        "stp x26, x25, [sp, #0x70]\n"
        "br x16\n"
    );
}

// QString::fromUtf8(const char *, qsizetype) 通过隐藏的 X8 返回地址写结果。
__attribute__((naked, noinline))
static void ar_sticker_qt_utf8_sret(uintptr_t function, void *result,
                                     const char *bytes, size_t length) {
    __asm__ volatile(
        "mov x16, x0\n"
        "mov x8, x1\n"
        "mov x0, x2\n"
        "mov x1, x3\n"
        "br x16\n"
    );
}

static void ar_sticker_qt_hide_menu(uintptr_t menu) {
    if (!menu || !ar_qt_inherits(menu, @"mmui::XMenu")) return;
    uintptr_t table = ar_pointer(menu);
    uintptr_t setVisible = ar_pointer(table + 0x68);
    if (setVisible) ((void (*)(void *, BOOL))setVisible)((void *)menu, NO);
}

static BOOL ar_sticker_qt_add_item(uintptr_t menu, ARStickerPayload *payload) {
    if (!menu || !payload || !gARStickerQtSlide ||
        !ar_qt_inherits(menu, @"mmui::XMenu")) return NO;

    uintptr_t style = ar_pointer(gARStickerQtSlide + kARQtDefaultStyleOffset);
    if (!style) return NO;

    void *(*allocate)(size_t) = (void *(*)(size_t))
        (gARStickerQtSlide + kARQtOperatorNewOffset);
    void (*deallocate)(void *, size_t) = (void (*)(void *, size_t))
        (gARStickerQtSlide + kARQtOperatorDeleteOffset);
    void *item = allocate(0x3e0);
    if (!item) return NO;

    static const char title[] = "导出表情…";
    uintptr_t qtTitle = 0;
    ar_sticker_qt_utf8_sret(gARStickerQtSlide + kARQtUtf8StringOffset,
                            &qtTitle, title, strlen(title));
    if (!qtTitle) {
        deallocate(item, 0x3e0);
        return NO;
    }

    void *(*construct)(void *, const uintptr_t *, void *, void *) =
        (void *(*)(void *, const uintptr_t *, void *, void *))
        (gARStickerQtSlide + kARQtXMenuItemCtorOffset);
    construct(item, &qtTitle, (void *)style, NULL);
    // 构造器和 QString 析构包装器都接收 QString 的地址；析构包装器会先从
    // [x0] 取共享数据指针再递减引用计数。不要调用外形相似但访问 +0x28 的
    // 0xb7078——它属于另一种对象，传入 QString 会在空地址处崩溃。
    ((void (*)(uintptr_t *))(gARStickerQtSlide + kARQtStringReleaseOffset))(&qtTitle);

    if (!ar_qt_inherits((uintptr_t)item, @"mmui::XMenuItem")) {
        ARLOG("WARN: Qt 表情菜单项构造校验失败");
        return NO;
    }

    // XMenu owns both the item and returned QAction. XMenuView is created
    // separately by the layout builder; this return value is NOT a view.
    void *action = ((void *(*)(void *, void *))
        (gARStickerQtSlide + kARQtXMenuAddOffset))((void *)menu, item);
    if (!action) {
        ARLOG("WARN: Qt 表情菜单项添加失败");
        return NO;
    }

    if (gARStickerQtItems.count > 32) [gARStickerQtItems removeAllObjects];
    gARStickerQtItems[@((uintptr_t)item)] = @{
        @"payload": payload,
        @"menu": @(menu),
    };
    ARLOG("STICKER_MENU_ADDED backend=qt");
    return YES;
}

static void ar_sticker_qt_layout(void *object) {
    uintptr_t menu = (uintptr_t)object;
    ARStickerPayload *payload = nil;
    NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
    if (gARStickerQtReady && gARStickerPendingPayload &&
        now - gARStickerPendingAt <= 2.0 && ar_qt_inherits(menu, @"mmui::XMenu"))
        payload = gARStickerPendingPayload;
    gARStickerPendingPayload = nil;
    gARStickerPendingAt = 0;
    if (payload) {
        [gARStickerQtItems removeAllObjects];
        ar_sticker_qt_add_item(menu, payload);
    }
    ar_sticker_qt_layout_original(object);

    // Log success only once a real row is present, not merely an action.
    if (payload) {
        NSMutableArray<NSNumber *> *views = [NSMutableArray array];
        ar_collect(menu, @"mmui::XMenuView", YES, views, [NSMutableSet set], 0, 500);
        for (NSNumber *number in views) {
            uintptr_t item = ar_pointer(number.unsignedLongLongValue + 0x1d8);
            if (gARStickerQtItems[@(item)]) {
                ARLOG("STICKER_MENU_READY backend=qt rendered=yes");
                break;
            }
        }
    }
}

static void ar_sticker_qt_clicked(void *object) {
    uintptr_t view = (uintptr_t)object;
    NSDictionary *record = nil;
    NSNumber *itemKey = nil;
    if (ar_qt_inherits(view, @"mmui::XMenuView")) {
        uintptr_t item = ar_pointer(view + 0x1d8);
        itemKey = @(item);
        record = gARStickerQtItems[itemKey];
    }
    ARStickerPayload *payload = [record[@"payload"]
        isKindOfClass:ARStickerPayload.class] ? record[@"payload"] : nil;
    NSNumber *menuNumber = [record[@"menu"] isKindOfClass:NSNumber.class]
        ? record[@"menu"] : nil;
    if (!payload || !menuNumber) {
        gARStickerQtActivate(object,
            (const void *)(gARStickerQtSlide + kARQtXViewMetaOffset), 0, NULL);
        return;
    }

    [gARStickerQtItems removeObjectForKey:itemKey];
    // 我们的项没有伪造微信内部回调对象，因此不广播这个 clicked；直接关闭
    // 当前 XMenu，并在退出 Qt 鼠标事件栈后启动下载/保存流程。
    ar_sticker_qt_hide_menu(menuNumber.unsignedLongLongValue);
    dispatch_async(dispatch_get_main_queue(), ^{
        [ARStickerExporter.shared exportPayload:payload];
    });
}

@interface NSApplication (ARStickerQtExport)
- (void)ar_sticker_sendEvent:(NSEvent *)event;
@end

@implementation NSApplication (ARStickerQtExport)
- (void)ar_sticker_sendEvent:(NSEvent *)event {
    if (gARStickerQtReady && ar_sticker_is_context_event(event)) {
        ARStickerPayload *payload = ar_sticker_payload_at_event(event, nil);
        gARStickerPendingPayload = payload;
        gARStickerPendingAt = payload ? [NSDate timeIntervalSinceReferenceDate] : 0;
    }
    [self ar_sticker_sendEvent:event];
}
@end

static BOOL ar_sticker_qt_start(const struct mach_header *header, uintptr_t slide) {
    if (!ar_marker_supported_core(header) || !slide) return NO;
    uintptr_t activate = slide + kARQtActivateOffset;
    uintptr_t layout = slide + kARQtXMenuLayoutOffset;
    uintptr_t clicked = slide + kARQtXViewClickedOffset;
    if (!ar_sticker_qt_signal_wrapper(clicked,
            slide + kARQtXViewMetaOffset, activate) ||
        !ar_sticker_qt_implementation_matches(slide)) {
        ARLOG("WARN: Qt 菜单 signal 指令校验失败，关闭表情导出");
        return NO;
    }

    gARStickerQtSlide = slide;
    gARStickerQtActivate = (void (*)(void *, const void *, int, void **))activate;
    gARStickerQtLayoutContinue = layout + 16;
    gARStickerQtItems = [NSMutableDictionary dictionary];

    // clicked 先装：即使 layout 安装失败，也只会原样转发已有点击。
    if (!install_arm64_trampoline(clicked, (uintptr_t)&ar_sticker_qt_clicked) ||
        !install_arm64_trampoline(layout, (uintptr_t)&ar_sticker_qt_layout)) {
        ARLOG("WARN: Qt 菜单跳板安装失败，关闭表情导出");
        return NO;
    }
    gARStickerQtReady = YES;
    BOOL eventHook = ar_sticker_exchange(
        class_getInstanceMethod(NSApplication.class, @selector(sendEvent:)),
        class_getInstanceMethod(NSApplication.class, @selector(ar_sticker_sendEvent:)));
    if (!eventHook) {
        gARStickerQtReady = NO;
        ARLOG("WARN: 未找到 NSApplication 事件入口，关闭表情导出");
        return NO;
    }
    ARLOG("STICKER_EXPORT_QT_READY");
    return YES;
}
#endif

@interface NSMenu (ARStickerExport)
+ (void)ar_sticker_popUpContextMenu:(NSMenu *)menu withEvent:(NSEvent *)event
                            forView:(NSView *)view;
- (BOOL)ar_sticker_popUpMenuPositioningItem:(NSMenuItem *)item
                                 atLocation:(NSPoint)location inView:(NSView *)view;
@end

@implementation NSMenu (ARStickerExport)
+ (void)ar_sticker_popUpContextMenu:(NSMenu *)menu withEvent:(NSEvent *)event
                            forView:(NSView *)view {
    ar_sticker_prepare_menu(menu, event, view);
    [self ar_sticker_popUpContextMenu:menu withEvent:event forView:view];
}
- (BOOL)ar_sticker_popUpMenuPositioningItem:(NSMenuItem *)item
                                 atLocation:(NSPoint)location inView:(NSView *)view {
    NSEvent *event = NSApp.currentEvent;
    if (ar_sticker_is_context_event(event)) ar_sticker_prepare_menu(self, event, view);
    return [self ar_sticker_popUpMenuPositioningItem:item atLocation:location inView:view];
}
@end

static BOOL ar_sticker_exchange(Method original, Method replacement) {
    if (!original || !replacement) return NO;
    method_exchangeImplementations(original, replacement);
    return YES;
}

static void ar_sticker_start(const struct mach_header *header, uintptr_t slide) {
#ifndef WECHATINTERCEPT_TEST
    static dispatch_once_t once;
    dispatch_once(&once, ^{
#if defined(__arm64__)
        if (!ar_sticker_database_start(header, slide))
            ARLOG("WARN: 表情数据库接口不匹配，关闭元数据读取");
        ar_sticker_qt_start(header, slide);
#else
        (void)header;
        (void)slide;
#endif
        Class menu = NSMenu.class;
        BOOL classHook = ar_sticker_exchange(
            class_getClassMethod(menu, @selector(popUpContextMenu:withEvent:forView:)),
            class_getClassMethod(menu, @selector(ar_sticker_popUpContextMenu:withEvent:forView:)));
        BOOL instanceHook = ar_sticker_exchange(
            class_getInstanceMethod(menu, @selector(popUpMenuPositioningItem:atLocation:inView:)),
            class_getInstanceMethod(menu, @selector(ar_sticker_popUpMenuPositioningItem:atLocation:inView:)));
        if (classHook || instanceHook) ARLOG("STICKER_EXPORT_APPKIT_READY");
        else ARLOG("WARN: 未找到原生右键菜单入口，关闭表情导出");
    });
#else
    (void)header;
    (void)slide;
#endif
}
