#include "pch.h"
#include "WebSocketObject.h"
#include "../../core/JSAnalyzer.h"
#include "../../hooks/HookType.h"
#include "../../builtin/helpers/SensitiveKeywordDetector.h"
#include <string>

namespace WebSocketObject {

static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
    return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
}

// ============================================================================
// Helper Functions
// ============================================================================

bool isSuspiciousUrl(const std::string& url) {
    if (url.find("ws://") == 0) return true;
    if (url.find("c2") != std::string::npos) return true;
    if (url.find("command") != std::string::npos) return true;
    if (url.find("control") != std::string::npos) return true;
    if (url.find("bot") != std::string::npos) return true;

    RE2 ip_pattern(R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})");
    return RE2::PartialMatch(url, ip_pattern);
}

bool containsSensitiveData(const std::string& data) {
    return SensitiveKeywordDetector::containsSensitiveKeyword(data);
}

bool isBase64Encoded(const std::string& data) {
    if (data.length() < 16) return false;
    RE2 base64_pattern("^[A-Za-z0-9+/]+=*$");
    return RE2::FullMatch(data, base64_pattern);
}

// ============================================================================
// Registration
// ============================================================================

void registerWebSocketObject(JSContext* ctx, JSValue global_obj) {
    // Create constructor
    JSValue ws_ctor = JS_NewCFunction2(ctx, js_websocket_constructor,
        "WebSocket", 2, JS_CFUNC_constructor, 0);

    // Create prototype
    JSValue proto = JS_NewObject(ctx);
    
    // Register methods
    JS_SetPropertyStr(ctx, proto, "send", 
        JS_NewCFunction(ctx, js_websocket_send, "send", 1));
    JS_SetPropertyStr(ctx, proto, "close", 
        JS_NewCFunction(ctx, js_websocket_close, "close", 2));

    // Register event handlers (setters)
    JSCFunctionType onmessage_setter_type;
    onmessage_setter_type.setter = js_websocket_set_onmessage;
    JSValue onmessage_setter = JS_NewCFunction2(ctx, onmessage_setter_type.generic,
        "set_onmessage", 1, JS_CFUNC_setter, 0);
    JS_DefinePropertyGetSet(ctx, proto, JS_NewAtom(ctx, "onmessage"),
        JS_UNDEFINED, onmessage_setter, JS_PROP_C_W_E);

    JSCFunctionType onerror_setter_type;
    onerror_setter_type.setter = js_websocket_set_onerror;
    JSValue onerror_setter = JS_NewCFunction2(ctx, onerror_setter_type.generic,
        "set_onerror", 1, JS_CFUNC_setter, 0);
    JS_DefinePropertyGetSet(ctx, proto, JS_NewAtom(ctx, "onerror"),
        JS_UNDEFINED, onerror_setter, JS_PROP_C_W_E);

    JSCFunctionType onopen_setter_type;
    onopen_setter_type.setter = js_websocket_set_onopen;
    JSValue onopen_setter = JS_NewCFunction2(ctx, onopen_setter_type.generic,
        "set_onopen", 1, JS_CFUNC_setter, 0);
    JS_DefinePropertyGetSet(ctx, proto, JS_NewAtom(ctx, "onopen"),
        JS_UNDEFINED, onopen_setter, JS_PROP_C_W_E);

    JSCFunctionType onclose_setter_type;
    onclose_setter_type.setter = js_websocket_set_onclose;
    JSValue onclose_setter = JS_NewCFunction2(ctx, onclose_setter_type.generic,
        "set_onclose", 1, JS_CFUNC_setter, 0);
    JS_DefinePropertyGetSet(ctx, proto, JS_NewAtom(ctx, "onclose"),
        JS_UNDEFINED, onclose_setter, JS_PROP_C_W_E);

    // Register getters
    JSCFunctionType readyState_getter_type;
    readyState_getter_type.getter = js_websocket_get_readyState;
    JSValue readyState_getter = JS_NewCFunction2(ctx, readyState_getter_type.generic,
        "get_readyState", 0, JS_CFUNC_getter, 0);
    JS_DefinePropertyGetSet(ctx, proto, JS_NewAtom(ctx, "readyState"),
        readyState_getter, JS_UNDEFINED, JS_PROP_C_W_E);

    JSCFunctionType url_getter_type;
    url_getter_type.getter = js_websocket_get_url;
    JSValue url_getter = JS_NewCFunction2(ctx, url_getter_type.generic,
        "get_url", 0, JS_CFUNC_getter, 0);
    JS_DefinePropertyGetSet(ctx, proto, JS_NewAtom(ctx, "url"),
        url_getter, JS_UNDEFINED, JS_PROP_C_W_E);

    JS_SetConstructor(ctx, ws_ctor, proto);
    JS_SetPropertyStr(ctx, global_obj, "WebSocket", ws_ctor);
}

// ============================================================================
// Constructor
// ============================================================================

JSValue js_websocket_constructor(JSContext* ctx, JSValueConst new_target, 
                                 int argc, JSValueConst* argv) {
    const char* url = argc > 0 ? JS_ToCString(ctx, argv[0]) : "";
    const char* protocols = argc > 1 ? JS_ToCString(ctx, argv[1]) : "";

    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::WEBSOCKET_CONNECT;
        event.line = 0;
        event.reason = "WebSocket connection - possible C&C communication";

        std::string url_str = url ? url : "";

        // Determine severity
        if (url_str.find("ws://") == 0) {
            event.severity = 10;
            event.reason += " (UNENCRYPTED ws://)";
            event.tags.insert("unencrypted");
        } else if (isSuspiciousUrl(url_str)) {
            event.severity = 9;
            event.tags.insert("suspicious_url");
        } else {
            event.severity = 8;
        }

        event.features["url"] = url_str;
        event.features["protocols"] = protocols ? protocols : "";
        event.tags.insert("remote_control");
        event.tags.insert("network");
        event.tags.insert("websocket");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    if (url) JS_FreeCString(ctx, url);
    if (protocols) JS_FreeCString(ctx, protocols);

    JSValue obj = JS_NewObjectClass(ctx, 0);
    JS_SetPropertyStr(ctx, obj, "_readyState", JS_NewInt32(ctx, 1));
    if (argc > 0) {
        JS_SetPropertyStr(ctx, obj, "_url", JS_DupValue(ctx, argv[0]));
    }

    return obj;
}

// ============================================================================
// Methods
// ============================================================================

JSValue js_websocket_send(JSContext* ctx, JSValueConst this_val, 
                         int argc, JSValueConst* argv) {
    if (argc < 1) return JS_UNDEFINED;

    const char* data = JS_ToCString(ctx, argv[0]);
    std::string data_str = data ? data : "";

    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::WEBSOCKET_SEND;
        event.line = 0;
        event.reason = "WebSocket send() - possible data exfiltration";

        // Determine severity
        if (containsSensitiveData(data_str)) {
            event.severity = 10;
            event.reason += " (SENSITIVE DATA)";
            event.tags.insert("data_exfiltration");
            event.tags.insert("sensitive_data");
        } else if (isBase64Encoded(data_str)) {
            event.severity = 8;
            event.reason += " (Base64 encoded)";
            event.tags.insert("encoded_data");
        } else if (data_str.find("command") != std::string::npos ||
                   data_str.find("cmd") != std::string::npos ||
                   data_str.find("exec") != std::string::npos) {
            event.severity = 9;
            event.reason += " (Command keywords)";
            event.tags.insert("command_execution");
        } else {
            event.severity = 7;
        }

        event.features["data"] = data_str.length() > 200 ?
            data_str.substr(0, 200) + "..." : data_str;
        event.features["data_length"] = static_cast<double>(data_str.length());
        event.tags.insert("remote_control");
        event.tags.insert("network");
        event.tags.insert("websocket");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    if (data) JS_FreeCString(ctx, data);
    return JS_UNDEFINED;
}

JSValue js_websocket_close(JSContext* ctx, JSValueConst this_val, 
                          int argc, JSValueConst* argv) {
    JS_SetPropertyStr(ctx, this_val, "_readyState", JS_NewInt32(ctx, 3));
    return JS_UNDEFINED;
}

// ============================================================================
// Event Handlers
// ============================================================================

JSValue js_websocket_set_onmessage(JSContext* ctx, JSValueConst this_val,
                                   JSValueConst val) {
    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::WEBSOCKET_MESSAGE;
        event.severity = 9;
        event.line = 0;
        event.reason = "WebSocket onmessage - receiving remote commands";
        
        // Analyze handler function
        if (JS_IsFunction(ctx, val)) {
            JSValue str_val = JS_ToString(ctx, val);
            const char* func_str = JS_ToCString(ctx, str_val);
            
            if (func_str) {
                std::string func_content(func_str);
                
                if (func_content.find("eval") != std::string::npos ||
                    func_content.find("Function") != std::string::npos) {
                    event.severity = 10;
                    event.reason += " (Contains eval/Function - RCE!)";
                    event.tags.insert("remote_code_execution");
                }
                
                event.features["handler_content"] = func_content.length() > 200 ?
                    func_content.substr(0, 200) + "..." : func_content;
                
                JS_FreeCString(ctx, func_str);
            }
            JS_FreeValue(ctx, str_val);
        }
        
        event.tags.insert("remote_control");
        event.tags.insert("event_handler");
        event.tags.insert("websocket");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    JS_SetPropertyStr(ctx, this_val, "_onmessage", JS_DupValue(ctx, val));
    return JS_UNDEFINED;
}

JSValue js_websocket_set_onerror(JSContext* ctx, JSValueConst this_val, 
                                 JSValueConst val) {
    JS_SetPropertyStr(ctx, this_val, "_onerror", JS_DupValue(ctx, val));
    return JS_UNDEFINED;
}

JSValue js_websocket_set_onopen(JSContext* ctx, JSValueConst this_val, 
                                JSValueConst val) {
    JS_SetPropertyStr(ctx, this_val, "_onopen", JS_DupValue(ctx, val));
    return JS_UNDEFINED;
}

JSValue js_websocket_set_onclose(JSContext* ctx, JSValueConst this_val, 
                                 JSValueConst val) {
    JS_SetPropertyStr(ctx, this_val, "_onclose", JS_DupValue(ctx, val));
    return JS_UNDEFINED;
}

// ============================================================================
// Getters
// ============================================================================

JSValue js_websocket_get_readyState(JSContext* ctx, JSValueConst this_val) {
    JSValue state = JS_GetPropertyStr(ctx, this_val, "_readyState");
    if (JS_IsUndefined(state)) {
        return JS_NewInt32(ctx, 1); // Default: OPEN
    }
    return state;
}

JSValue js_websocket_get_url(JSContext* ctx, JSValueConst this_val) {
    JSValue url = JS_GetPropertyStr(ctx, this_val, "_url");
    if (JS_IsUndefined(url)) {
        return JS_NewString(ctx, "");
    }
    return url;
}

} // namespace WebSocketObject
