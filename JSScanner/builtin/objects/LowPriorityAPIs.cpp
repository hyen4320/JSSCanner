#include "pch.h"
#include "LowPriorityAPIs.h"
#include "../../core/JSAnalyzer.h"
#include "../../hooks/HookType.h"

namespace LowPriorityAPIs {

static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
    return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
}

void registerLowPriorityAPIs(JSContext* ctx, JSValue global_obj) {
    // Notification
    JSValue notif_ctor = JS_NewCFunction2(ctx, js_notification_constructor,
        "Notification", 2, JS_CFUNC_constructor, 0);
    JS_SetPropertyStr(ctx, notif_ctor, "requestPermission", 
        JS_NewCFunction(ctx, js_notification_requestPermission, "requestPermission", 0));
    JS_SetPropertyStr(ctx, global_obj, "Notification", notif_ctor);

    // Geolocation
    JSValue navigator = JS_GetPropertyStr(ctx, global_obj, "navigator");
    if (JS_IsUndefined(navigator)) {
        navigator = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, global_obj, "navigator", navigator);
    }
    
    JSValue geolocation = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, geolocation, "getCurrentPosition", 
        JS_NewCFunction(ctx, js_geolocation_getCurrentPosition, "getCurrentPosition", 3));
    JS_SetPropertyStr(ctx, geolocation, "watchPosition", 
        JS_NewCFunction(ctx, js_geolocation_watchPosition, "watchPosition", 3));
    JS_SetPropertyStr(ctx, navigator, "geolocation", geolocation);

    // Clipboard
    JSValue clipboard = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, clipboard, "writeText", 
        JS_NewCFunction(ctx, js_clipboard_writeText, "writeText", 1));
    JS_SetPropertyStr(ctx, clipboard, "readText", 
        JS_NewCFunction(ctx, js_clipboard_readText, "readText", 0));
    JS_SetPropertyStr(ctx, navigator, "clipboard", clipboard);

    // WebRTC
    JSValue rtc_ctor = JS_NewCFunction2(ctx, js_rtc_peerconnection_constructor,
        "RTCPeerConnection", 1, JS_CFUNC_constructor, 0);
    JS_SetPropertyStr(ctx, global_obj, "RTCPeerConnection", rtc_ctor);

    // requestAnimationFrame
    JS_SetPropertyStr(ctx, global_obj, "requestAnimationFrame", 
        JS_NewCFunction(ctx, js_requestAnimationFrame, "requestAnimationFrame", 1));
}

// ============================================================================
// Notification
// ============================================================================

JSValue js_notification_constructor(JSContext* ctx, JSValueConst new_target, 
                                   int argc, JSValueConst* argv) {
    const char* title = argc > 0 ? JS_ToCString(ctx, argv[0]) : "";
    
    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::NOTIFICATION_CREATE;
        event.severity = 6;
        event.line = 0;
        event.reason = "Notification created - potential phishing alert";
        event.features["title"] = title ? title : "";
        event.tags.insert("notification");
        event.tags.insert("social_engineering");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    if (title && argc > 0) JS_FreeCString(ctx, title);
    return JS_NewObjectClass(ctx, 0);
}

JSValue js_notification_requestPermission(JSContext* ctx, JSValueConst this_val, 
                                         int argc, JSValueConst* argv) {
    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::NOTIFICATION_PERMISSION;
        event.severity = 5;
        event.line = 0;
        event.reason = "Notification.requestPermission";
        event.tags.insert("notification");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    JSValue promise = JS_NewObject(ctx);
    return promise;
}

// ============================================================================
// Geolocation
// ============================================================================

JSValue js_geolocation_getCurrentPosition(JSContext* ctx, JSValueConst this_val, 
                                         int argc, JSValueConst* argv) {
    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::GEOLOCATION_GET;
        event.severity = 7;
        event.line = 0;
        event.reason = "geolocation.getCurrentPosition - location tracking";
        event.tags.insert("privacy");
        event.tags.insert("location");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    return JS_UNDEFINED;
}

JSValue js_geolocation_watchPosition(JSContext* ctx, JSValueConst this_val, 
                                    int argc, JSValueConst* argv) {
    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::GEOLOCATION_WATCH;
        event.severity = 8;
        event.line = 0;
        event.reason = "geolocation.watchPosition - continuous location tracking";
        event.tags.insert("privacy");
        event.tags.insert("location");
        event.tags.insert("surveillance");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    return JS_NewInt32(ctx, 1); // Return fake watch ID
}

// ============================================================================
// Clipboard
// ============================================================================

JSValue js_clipboard_writeText(JSContext* ctx, JSValueConst this_val, 
                               int argc, JSValueConst* argv) {
    const char* text = argc > 0 ? JS_ToCString(ctx, argv[0]) : "";
    
    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::CLIPBOARD_WRITE;
        event.severity = 8;
        event.line = 0;
        event.reason = "clipboard.writeText - clipboard hijacking";
        event.features["text"] = text ? text : "";
        event.tags.insert("privacy");
        event.tags.insert("clipboard");
        event.tags.insert("hijacking");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    if (text && argc > 0) JS_FreeCString(ctx, text);
    
    JSValue promise = JS_NewObject(ctx);
    return promise;
}

JSValue js_clipboard_readText(JSContext* ctx, JSValueConst this_val, 
                              int argc, JSValueConst* argv) {
    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::CLIPBOARD_READ;
        event.severity = 9;
        event.line = 0;
        event.reason = "clipboard.readText - stealing clipboard content";
        event.tags.insert("privacy");
        event.tags.insert("clipboard");
        event.tags.insert("data_theft");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    JSValue promise = JS_NewObject(ctx);
    return promise;
}

// ============================================================================
// WebRTC
// ============================================================================

JSValue js_rtc_peerconnection_constructor(JSContext* ctx, JSValueConst new_target, 
                                          int argc, JSValueConst* argv) {
    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::WEBRTC_CREATE;
        event.severity = 7;
        event.line = 0;
        event.reason = "RTCPeerConnection - potential IP leak";
        event.tags.insert("privacy");
        event.tags.insert("webrtc");
        event.tags.insert("ip_leak");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    JSValue obj = JS_NewObjectClass(ctx, 0);
    JS_SetPropertyStr(ctx, obj, "createDataChannel", 
        JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, 
                                int argc, JSValueConst* argv) -> JSValue {
            JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
                HookEvent event;
                event.hookType = HookType::WEBRTC_DATA_CHANNEL;
                event.severity = 7;
                event.line = 0;
                event.reason = "RTCPeerConnection.createDataChannel";
                event.tags.insert("webrtc");

                a_ctx->dynamicAnalyzer->recordEvent(event);
            }
            return JS_NewObject(ctx);
        }, "createDataChannel", 2));
    
    return obj;
}

// ============================================================================
// requestAnimationFrame
// ============================================================================

JSValue js_requestAnimationFrame(JSContext* ctx, JSValueConst this_val, 
                                 int argc, JSValueConst* argv) {
    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::RAF_CREATE;
        event.severity = 4;
        event.line = 0;
        event.reason = "requestAnimationFrame - potential timing attack";
        event.tags.insert("timing_attack");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    return JS_NewInt32(ctx, 1); // Return fake request ID
}

} // namespace LowPriorityAPIs
