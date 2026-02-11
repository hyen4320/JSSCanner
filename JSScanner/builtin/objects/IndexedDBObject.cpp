#include "pch.h"
#include "IndexedDBObject.h"
#include "../../core/JSAnalyzer.h"
#include "../../hooks/HookType.h"
#include "../../builtin/helpers/SensitiveKeywordDetector.h"

namespace IndexedDBObject {

static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
    return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
}

void registerIndexedDBObject(JSContext* ctx, JSValue global_obj) {
    // Create indexedDB object
    JSValue indexedDB = JS_NewObject(ctx);
    
    JS_SetPropertyStr(ctx, indexedDB, "open", 
        JS_NewCFunction(ctx, js_indexeddb_open, "open", 2));

    JS_SetPropertyStr(ctx, global_obj, "indexedDB", indexedDB);
}

JSValue js_indexeddb_open(JSContext* ctx, JSValueConst this_val, 
                         int argc, JSValueConst* argv) {
    if (argc < 1) return JS_UNDEFINED;

    const char* db_name = JS_ToCString(ctx, argv[0]);
    std::string name = db_name ? db_name : "";
    int version = argc > 1 ? 1 : 0;

    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::INDEXEDDB_OPEN;
        event.severity = 8;
        event.line = 0;
        event.reason = "IndexedDB opened - potential persistent storage";

        event.features["database_name"] = name;
        event.features["version"] = version;
        event.tags.insert("storage");
        event.tags.insert("persistence");
        event.tags.insert("indexeddb");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    if (db_name) JS_FreeCString(ctx, db_name);

    // Return mock IDBOpenDBRequest
    JSValue request = JS_NewObject(ctx);
    
    // Add transaction method
    JSValue db = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, db, "transaction", 
        JS_NewCFunction(ctx, js_idbdatabase_transaction, "transaction", 2));
    
    // Simulate async success
    JS_SetPropertyStr(ctx, request, "result", db);
    JS_SetPropertyStr(ctx, request, "readyState", JS_NewString(ctx, "done"));
    
    return request;
}

JSValue js_idbdatabase_transaction(JSContext* ctx, JSValueConst this_val,
                                  int argc, JSValueConst* argv) {
    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::INDEXEDDB_TRANSACTION;
        event.severity = 7;
        event.line = 0;
        event.reason = "IndexedDB transaction started";
        event.tags.insert("storage");
        event.tags.insert("indexeddb");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    JSValue transaction = JS_NewObject(ctx);
    JSValue objectStore = JS_NewObject(ctx);
    
    JS_SetPropertyStr(ctx, objectStore, "add", 
        JS_NewCFunction(ctx, js_idbobjectstore_add, "add", 2));
    JS_SetPropertyStr(ctx, objectStore, "put", 
        JS_NewCFunction(ctx, js_idbobjectstore_put, "put", 2));
    
    JS_SetPropertyStr(ctx, transaction, "objectStore", 
        JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, 
                                int argc, JSValueConst* argv) -> JSValue {
            JSValue store = JS_NewObject(ctx);
            JS_SetPropertyStr(ctx, store, "add", 
                JS_NewCFunction(ctx, js_idbobjectstore_add, "add", 2));
            JS_SetPropertyStr(ctx, store, "put", 
                JS_NewCFunction(ctx, js_idbobjectstore_put, "put", 2));
            return store;
        }, "objectStore", 1));
    
    return transaction;
}

JSValue js_idbobjectstore_add(JSContext* ctx, JSValueConst this_val, 
                              int argc, JSValueConst* argv) {
    if (argc < 1) return JS_UNDEFINED;

    const char* value = JS_ToCString(ctx, argv[0]);
    std::string val_str = value ? value : "";

    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::INDEXEDDB_ADD;
        event.line = 0;
        event.reason = "IndexedDB data stored";

        if (SensitiveKeywordDetector::containsSensitiveKeyword(val_str)) {
            event.severity = 10;
            event.reason += " (SENSITIVE DATA)";
            event.tags.insert("data_theft");
        } else if (val_str.length() > 1024 * 1024) {
            event.severity = 8;
            event.reason += " (Large data >1MB)";
        } else {
            event.severity = 7;
        }

        event.features["value"] = val_str.length() > 200 ?
            val_str.substr(0, 200) + "..." : val_str;
        event.features["data_size"] = static_cast<double>(val_str.length());
        event.tags.insert("storage");
        event.tags.insert("indexeddb");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    if (value) JS_FreeCString(ctx, value);
    return JS_NewObject(ctx);
}

JSValue js_idbobjectstore_put(JSContext* ctx, JSValueConst this_val, 
                              int argc, JSValueConst* argv) {
    return js_idbobjectstore_add(ctx, this_val, argc, argv);
}

} // namespace IndexedDBObject
