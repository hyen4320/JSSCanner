#include "pch.h"
#include "NavigatorObject.h"
#include "../../core/JSAnalyzer.h"
#include "../../hooks/HookType.h"
#include "../../builtin/helpers/SensitiveKeywordDetector.h"

namespace NavigatorObject {

static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
    return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
}

void registerNavigatorObject(JSContext* ctx, JSValue global_obj) {
    JSValue navigator = JS_GetPropertyStr(ctx, global_obj, "navigator");
    if (JS_IsUndefined(navigator)) {
        navigator = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, global_obj, "navigator", navigator);
    }

    JS_SetPropertyStr(ctx, navigator, "sendBeacon", 
        JS_NewCFunction(ctx, js_navigator_sendBeacon, "sendBeacon", 2));
}

JSValue js_navigator_sendBeacon(JSContext* ctx, JSValueConst this_val, 
                                int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewBool(ctx, false);

    const char* url = JS_ToCString(ctx, argv[0]);
    const char* data = argc > 1 ? JS_ToCString(ctx, argv[1]) : "";
    
    std::string url_str = url ? url : "";
    std::string data_str = data ? data : "";

    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::NAVIGATOR_SEND_BEACON;
        event.line = 0;
        event.reason = "navigator.sendBeacon - async data transmission";
        
        if (SensitiveKeywordDetector::containsSensitiveKeyword(data_str)) {
            event.severity = 10;
            event.reason += " (SENSITIVE DATA)";
            event.tags.insert("data_exfiltration");
        } else {
            event.severity = 8;
        }
        
        event.features["url"] = url_str;
        event.features["data"] = data_str.length() > 200 ? 
            data_str.substr(0, 200) + "..." : data_str;
        event.tags.insert("network");
        event.tags.insert("beacon");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    if (url) JS_FreeCString(ctx, url);
    if (data && argc > 1) JS_FreeCString(ctx, data);
    
    return JS_NewBool(ctx, true);
}

} // namespace NavigatorObject
