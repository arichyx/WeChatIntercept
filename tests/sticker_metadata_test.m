#define WECHATINTERCEPT_TEST 1
#include "../hook.m"
#include <sqlite3.h>
#include <assert.h>

int main(void) {
    @autoreleasepool {
        char directory[] = "/private/tmp/WeChatIntercept-stickers.XXXXXX";
        assert(mkdtemp(directory));
        NSString *root = [NSString stringWithUTF8String:directory];
        NSString *path = [root stringByAppendingPathComponent:@"emoticon.db"];
        sqlite3 *database = NULL;
        assert(sqlite3_open(path.UTF8String, &database) == SQLITE_OK);
        gARSQLiteExec = sqlite3_exec;
        gARSQLiteDBFilename = sqlite3_db_filename;

        // Failed/early schema reads must not prevent later successful reads.
        assert(ar_sticker_try_load_metadata(database));
        assert(!gARStickerMetadata);
        assert(sqlite3_exec(database,
            "CREATE TABLE kNonStoreEmoticonTable(md5 TEXT,aes_key TEXT,tp_url TEXT,"
            "cdn_url TEXT,extern_url TEXT,encrypt_url TEXT);"
            "INSERT INTO kNonStoreEmoticonTable VALUES("
            "'0123456789abcdef0123456789abcdef',"
            "'00112233445566778899aabbccddeeff',NULL,"
            "'https://emoji.qpic.cn/original.gif',NULL,"
            "'https://emoji.qpic.cn/encrypted');", NULL, NULL, NULL) == SQLITE_OK);
        assert(ar_sticker_try_load_metadata(database));
        ARStickerPayload *message = ar_sticker_payload_from_attributes(
            @{@"md5": @"0123456789abcdef0123456789abcdef"});
        ARStickerPayload *result = ar_sticker_enrich_payload(message);
        assert(result.plainURLs.count == 1 && result.aesKey.length == 16);
        assert([result.encryptedURL.path isEqualToString:@"/encrypted"]);

        // Partial message fields cannot pair a stale URL with a different key.
        message.encryptedURL = [NSURL URLWithString:@"https://emoji.qpic.cn/stale"];
        result = ar_sticker_enrich_payload(message);
        assert([result.encryptedURL.path isEqualToString:@"/encrypted"]);
        assert(result.aesKey.length == 16);

        // The cache must refresh, including a successful empty result.
        assert(sqlite3_exec(database,
            "UPDATE kNonStoreEmoticonTable SET cdn_url='https://emoji.qpic.cn/new.gif';",
            NULL, NULL, NULL) == SQLITE_OK);
        assert(ar_sticker_try_load_metadata(database));
        assert([ar_sticker_enrich_payload(message).plainURLs.firstObject.path
                isEqualToString:@"/new.gif"]);
        assert(sqlite3_exec(database, "DELETE FROM kNonStoreEmoticonTable",
            NULL, NULL, NULL) == SQLITE_OK);
        assert(ar_sticker_try_load_metadata(database));
        assert(gARStickerMetadata.count == 0);

        NSUInteger attempts = gARStickerMetadataAttempts;
        gARStickerInsideMetadataQuery = YES;
        assert(!ar_sticker_try_load_metadata(database));
        gARStickerInsideMetadataQuery = NO;
        assert(gARStickerMetadataAttempts == attempts);
        sqlite3_close(database);

        assert(sqlite3_open(":memory:", &database) == SQLITE_OK);
        assert(!ar_sticker_try_load_metadata(database));
        sqlite3_close(database);
        assert(!ar_sticker_emoticon_db_path("/private/tmp/not-emoticon.db"));
        assert(ar_sticker_emoticon_db_path("/private/tmp/emoticon.db"));
        assert(ar_sticker_payload_from_attributes(@{
            @"md5": @"0123456789abcdef0123456789abcdef",
            @"thumburl": @"https://emoji.qpic.cn/thumbnail.png"
        }).plainURLs.count == 0);
        assert([[NSFileManager defaultManager] removeItemAtPath:root error:NULL]);
        puts("PASS: live SQLite metadata refresh, isolation, URL/key pairing, original-only URLs");
    }
    return 0;
}
