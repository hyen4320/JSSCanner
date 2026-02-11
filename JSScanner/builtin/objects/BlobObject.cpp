#include "pch.h"
#include "BlobObject.h"
#include "../../core/JSAnalyzer.h"
#include "../../hooks/HookType.h"

namespace BlobObject {

static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
    return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
}

void registerBlobObject(JSContext* ctx, JSValue global_obj) {
    // Blob constructor
    JSValue blob_ctor = JS_NewCFunction2(ctx, js_blob_constructor,
        "Blob", 2, JS_CFUNC_constructor, 0);
    JS_SetPropertyStr(ctx, global_obj, "Blob", blob_ctor);

    // URL object
    JSValue url_obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, url_obj, "createObjectURL", 
        JS_NewCFunction(ctx, js_url_createObjectURL, "createObjectURL", 1));
    JS_SetPropertyStr(ctx, url_obj, "revokeObjectURL", 
        JS_NewCFunction(ctx, js_url_revokeObjectURL, "revokeObjectURL", 1));
    JS_SetPropertyStr(ctx, global_obj, "URL", url_obj);
}

JSValue js_blob_constructor(JSContext* ctx, JSValueConst new_target, 
                           int argc, JSValueConst* argv) {
    std::string content;
    std::string type = "text/plain";

    if (argc > 0 && JS_IsArray(argv[0])) {
        JSValue len_val = JS_GetPropertyStr(ctx, argv[0], "length");
        int len = 0;
        JS_ToInt32(ctx, &len, len_val);
        JS_FreeValue(ctx, len_val);
        
        for (int i = 0; i < len; i++) {
            JSValue item = JS_GetPropertyUint32(ctx, argv[0], i);
            const char* str = JS_ToCString(ctx, item);
            if (str) {
                content += str;
                JS_FreeCString(ctx, str);
            }
            JS_FreeValue(ctx, item);
        }
    }

    if (argc > 1 && JS_IsObject(argv[1])) {
        JSValue type_val = JS_GetPropertyStr(ctx, argv[1], "type");
        const char* type_str = JS_ToCString(ctx, type_val);
        if (type_str) {
            type = type_str;
            JS_FreeCString(ctx, type_str);
        }
        JS_FreeValue(ctx, type_val);
    }

    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::BLOB_CREATE;
        event.line = 0;
        event.reason = "Blob created - potential file generation";

        if (type.find("javascript") != std::string::npos ||
            type.find("html") != std::string::npos ||
            content.find("<script") != std::string::npos) {
            event.severity = 9;
            event.reason += " (Executable content)";
            event.tags.insert("code_injection");
        } else {
            event.severity = 7;
        }

        event.features["type"] = type;
        event.features["size"] = static_cast<double>(content.length());
        event.features["content"] = content.length() > 200 ?
            content.substr(0, 200) + "..." : content;
        event.tags.insert("file_creation");
        event.tags.insert("blob");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    JSValue obj = JS_NewObjectClass(ctx, 0);
    JS_SetPropertyStr(ctx, obj, "type", JS_NewString(ctx, type.c_str()));
    JS_SetPropertyStr(ctx, obj, "size", JS_NewInt32(ctx, content.length()));
    return obj;
}

JSValue js_url_createObjectURL(JSContext* ctx, JSValueConst this_val,
                               int argc, JSValueConst* argv) {
    if (argc < 1) return JS_UNDEFINED;

    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::URL_CREATE_OBJECT_URL;
        event.severity = 8;
        event.line = 0;
        event.reason = "URL.createObjectURL - Blob URL created";
        event.tags.insert("file_creation");
        event.tags.insert("obfuscation");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    return JS_NewString(ctx, "blob:http://localhost/fake-uuid");
}

JSValue js_url_revokeObjectURL(JSContext* ctx, JSValueConst this_val, 
                               int argc, JSValueConst* argv) {
    return JS_UNDEFINED;
}

} // namespace BlobObject
