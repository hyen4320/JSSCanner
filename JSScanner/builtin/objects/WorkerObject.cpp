#include "pch.h"
#include "WorkerObject.h"
#include "../../core/JSAnalyzer.h"
#include "../../hooks/HookType.h"
#include "../../builtin/helpers/SensitiveKeywordDetector.h"
#include <string>

namespace WorkerObject {

static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
    return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
}

// ============================================================================
// Helper Functions
// ============================================================================

static bool isBlobUrl(const std::string& url) {
    return url.find("blob:") == 0;
}

static bool isDataUrl(const std::string& url) {
    return url.find("data:") == 0;
}

// Helper functions for MessagePort
static JSValue js_messageport_start(JSContext* ctx, JSValueConst this_val,
                                     int argc, JSValueConst* argv) {
    return JS_UNDEFINED;
}

static JSValue js_messageport_close(JSContext* ctx, JSValueConst this_val,
                                     int argc, JSValueConst* argv) {
    return JS_UNDEFINED;
}

// ============================================================================
// Registration
// ============================================================================

void registerWorkerObject(JSContext* ctx, JSValue global_obj) {
    // Worker
    JSValue worker_ctor = JS_NewCFunction2(ctx, js_worker_constructor,
        "Worker", 2, JS_CFUNC_constructor, 0);

    JSValue proto = JS_NewObject(ctx);
    
    JS_SetPropertyStr(ctx, proto, "postMessage",
        JS_NewCFunction(ctx, js_worker_postMessage, "postMessage", 1));
    JS_SetPropertyStr(ctx, proto, "terminate",
        JS_NewCFunction(ctx, js_worker_terminate, "terminate", 0));

    JSCFunctionType onmessage_setter_type;
    onmessage_setter_type.setter = js_worker_set_onmessage;
    JSValue onmessage_setter = JS_NewCFunction2(ctx, onmessage_setter_type.generic,
        "set_onmessage", 1, JS_CFUNC_setter, 0);
    JS_DefinePropertyGetSet(ctx, proto, JS_NewAtom(ctx, "onmessage"),
        JS_UNDEFINED, onmessage_setter, JS_PROP_C_W_E);

    JSCFunctionType onerror_setter_type;
    onerror_setter_type.setter = js_worker_set_onerror;
    JSValue onerror_setter = JS_NewCFunction2(ctx, onerror_setter_type.generic,
        "set_onerror", 1, JS_CFUNC_setter, 0);
    JS_DefinePropertyGetSet(ctx, proto, JS_NewAtom(ctx, "onerror"),
        JS_UNDEFINED, onerror_setter, JS_PROP_C_W_E);

    JS_SetConstructor(ctx, worker_ctor, proto);
    JS_SetPropertyStr(ctx, global_obj, "Worker", worker_ctor);

    // SharedWorker
    JSValue sharedworker_ctor = JS_NewCFunction2(ctx, js_sharedworker_constructor,
        "SharedWorker", 2, JS_CFUNC_constructor, 0);
    JS_SetPropertyStr(ctx, global_obj, "SharedWorker", sharedworker_ctor);
}

// ============================================================================
// Constructor
// ============================================================================

JSValue js_worker_constructor(JSContext* ctx, JSValueConst new_target, 
                              int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "Worker requires script URL");
    }

    const char* script_url = JS_ToCString(ctx, argv[0]);
    std::string url = script_url ? script_url : "";

    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::WORKER_CREATE;
        event.line = 0;
        event.reason = "Worker created - background script execution";

        if (isBlobUrl(url)) {
            event.severity = 9;
            event.reason += " (Blob URL - obfuscated script)";
            event.tags.insert("obfuscation");
        } else if (isDataUrl(url)) {
            event.severity = 9;
            event.reason += " (Data URL - inline script)";
            event.tags.insert("inline_script");
        } else {
            event.severity = 8;
        }

        event.features["script_url"] = url;
        event.tags.insert("background_execution");
        event.tags.insert("worker");
        event.tags.insert("threading");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    if (script_url) JS_FreeCString(ctx, script_url);

    JSValue obj = JS_NewObjectClass(ctx, 0);
    JS_SetPropertyStr(ctx, obj, "_scriptUrl", JS_DupValue(ctx, argv[0]));
    return obj;
}

// ============================================================================
// Methods
// ============================================================================

JSValue js_worker_postMessage(JSContext* ctx, JSValueConst this_val, 
                              int argc, JSValueConst* argv) {
    if (argc < 1) return JS_UNDEFINED;

    const char* message = JS_ToCString(ctx, argv[0]);
    std::string msg_str = message ? message : "";

    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::WORKER_POST_MESSAGE;
        event.line = 0;
        event.reason = "Worker.postMessage - data transfer to background";

        if (SensitiveKeywordDetector::containsSensitiveKeyword(msg_str)) {
            event.severity = 10;
            event.reason += " (SENSITIVE DATA)";
            event.tags.insert("data_exfiltration");
        } else {
            event.severity = 7;
        }

        event.features["message"] = msg_str.length() > 200 ?
            msg_str.substr(0, 200) + "..." : msg_str;
        event.tags.insert("worker");
        event.tags.insert("background_execution");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    if (message) JS_FreeCString(ctx, message);
    return JS_UNDEFINED;
}

JSValue js_worker_terminate(JSContext* ctx, JSValueConst this_val, 
                            int argc, JSValueConst* argv) {
    return JS_UNDEFINED;
}

// ============================================================================
// Event Handlers
// ============================================================================

JSValue js_worker_set_onmessage(JSContext* ctx, JSValueConst this_val, 
                                JSValueConst val) {
    JS_SetPropertyStr(ctx, this_val, "_onmessage", JS_DupValue(ctx, val));
    return JS_UNDEFINED;
}

JSValue js_worker_set_onerror(JSContext* ctx, JSValueConst this_val,
                              JSValueConst val) {
    JS_SetPropertyStr(ctx, this_val, "_onerror", JS_DupValue(ctx, val));
    return JS_UNDEFINED;
}

// ============================================================================
// SharedWorker Constructor
// ============================================================================

JSValue js_sharedworker_constructor(JSContext* ctx, JSValueConst new_target, 
                                    int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "SharedWorker requires script URL");
    }

    const char* script_url = JS_ToCString(ctx, argv[0]);
    const char* name = argc > 1 ? JS_ToCString(ctx, argv[1]) : "";
    
    std::string url = script_url ? script_url : "";
    std::string worker_name = name ? name : "";

    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::SHARED_WORKER_CREATE;
        event.line = 0;
        event.reason = "SharedWorker created - cross-tab communication";

        if (isBlobUrl(url)) {
            event.severity = 10;
            event.reason += " (Blob URL - obfuscated cross-tab script)";
            event.tags.insert("obfuscation");
        } else if (isDataUrl(url)) {
            event.severity = 10;
            event.reason += " (Data URL - inline cross-tab script)";
            event.tags.insert("inline_script");
        } else {
            event.severity = 9;
        }

        event.features["script_url"] = url;
        event.features["worker_name"] = worker_name;
        event.tags.insert("background_execution");
        event.tags.insert("shared_worker");
        event.tags.insert("cross_tab_communication");
        event.tags.insert("persistence");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    if (script_url) JS_FreeCString(ctx, script_url);
    if (name && argc > 1) JS_FreeCString(ctx, name);

    // Create SharedWorker object with port property
    JSValue obj = JS_NewObjectClass(ctx, 0);
    JS_SetPropertyStr(ctx, obj, "_scriptUrl", JS_DupValue(ctx, argv[0]));
    
    // Create MessagePort object for cross-tab communication
    JSValue port = JS_NewObject(ctx);
    JSValue postMessage_func = JS_NewCFunction(ctx, js_worker_postMessage, "postMessage", 1);
    JSValue start_func = JS_NewCFunction(ctx, js_messageport_start, "start", 0);
    JSValue close_func = JS_NewCFunction(ctx, js_messageport_close, "close", 0);

    JS_SetPropertyStr(ctx, port, "postMessage", postMessage_func);
    JS_SetPropertyStr(ctx, port, "start", start_func);
    JS_SetPropertyStr(ctx, port, "close", close_func);

    JS_SetPropertyStr(ctx, obj, "port", port);
    
    return obj;
}

} // namespace WorkerObject
