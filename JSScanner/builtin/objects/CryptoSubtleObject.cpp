#include "pch.h"
#include "CryptoSubtleObject.h"
#include "../../core/JSAnalyzer.h"
#include "../../hooks/HookType.h"

namespace CryptoSubtleObject {

static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
    return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
}

void registerCryptoSubtleObject(JSContext* ctx, JSValue global_obj) {
    // Get or create crypto object
    JSValue crypto = JS_GetPropertyStr(ctx, global_obj, "crypto");
    if (JS_IsUndefined(crypto)) {
        crypto = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, global_obj, "crypto", crypto);
    }

    // Create subtle object
    JSValue subtle = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, subtle, "encrypt", 
        JS_NewCFunction(ctx, js_crypto_subtle_encrypt, "encrypt", 3));
    JS_SetPropertyStr(ctx, subtle, "decrypt", 
        JS_NewCFunction(ctx, js_crypto_subtle_decrypt, "decrypt", 3));
    JS_SetPropertyStr(ctx, subtle, "importKey", 
        JS_NewCFunction(ctx, js_crypto_subtle_importKey, "importKey", 5));
    JS_SetPropertyStr(ctx, subtle, "generateKey", 
        JS_NewCFunction(ctx, js_crypto_subtle_generateKey, "generateKey", 3));

    JS_SetPropertyStr(ctx, crypto, "subtle", subtle);
}

JSValue js_crypto_subtle_encrypt(JSContext* ctx, JSValueConst this_val, 
                                 int argc, JSValueConst* argv) {
    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::CRYPTO_ENCRYPT;
        event.severity = 8;
        event.line = 0;
        event.reason = "crypto.subtle.encrypt - encrypting data";
        event.tags.insert("crypto");
        event.tags.insert("encryption");
        event.tags.insert("obfuscation");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    // Return promise
    JSValue promise = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, promise, "then", 
        JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, 
                                int argc, JSValueConst* argv) -> JSValue {
            return JS_UNDEFINED;
        }, "then", 1));
    return promise;
}

JSValue js_crypto_subtle_decrypt(JSContext* ctx, JSValueConst this_val, 
                                 int argc, JSValueConst* argv) {
    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::CRYPTO_DECRYPT;
        event.severity = 8;
        event.line = 0;
        event.reason = "crypto.subtle.decrypt - decrypting payload";
        event.tags.insert("crypto");
        event.tags.insert("decryption");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    JSValue promise = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, promise, "then", 
        JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, 
                                int argc, JSValueConst* argv) -> JSValue {
            return JS_UNDEFINED;
        }, "then", 1));
    return promise;
}

JSValue js_crypto_subtle_importKey(JSContext* ctx, JSValueConst this_val, 
                                   int argc, JSValueConst* argv) {
    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::CRYPTO_IMPORT_KEY;
        event.severity = 7;
        event.line = 0;
        event.reason = "crypto.subtle.importKey - importing encryption key";
        event.tags.insert("crypto");
        event.tags.insert("key_management");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    JSValue promise = JS_NewObject(ctx);
    return promise;
}

JSValue js_crypto_subtle_generateKey(JSContext* ctx, JSValueConst this_val, 
                                     int argc, JSValueConst* argv) {
    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::CRYPTO_IMPORT_KEY;
        event.severity = 7;
        event.line = 0;
        event.reason = "crypto.subtle.generateKey - generating encryption key";
        event.tags.insert("crypto");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    JSValue promise = JS_NewObject(ctx);
    return promise;
}

} // namespace CryptoSubtleObject
