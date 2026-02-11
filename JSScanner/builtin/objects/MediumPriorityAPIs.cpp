#include "pch.h"
#include "MediumPriorityAPIs.h"
#include "../../core/JSAnalyzer.h"
#include "../../hooks/HookType.h"
#include "../../builtin/helpers/SensitiveKeywordDetector.h"

namespace MediumPriorityAPIs {

static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
    return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
}

void registerMediumPriorityAPIs(JSContext* ctx, JSValue global_obj) {
    // ShadowDOM - Element.prototype.attachShadow
    JSValue element_proto = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, element_proto, "attachShadow", 
        JS_NewCFunction(ctx, js_element_attachShadow, "attachShadow", 1));
    JS_SetPropertyStr(ctx, global_obj, "Element", element_proto);

    // MutationObserver
    JSValue mo_ctor = JS_NewCFunction2(ctx, js_mutation_observer_constructor,
        "MutationObserver", 1, JS_CFUNC_constructor, 0);
    JS_SetPropertyStr(ctx, global_obj, "MutationObserver", mo_ctor);

    // SessionStorage
    JSValue sessionStorage = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, sessionStorage, "setItem", 
        JS_NewCFunction(ctx, js_sessionstorage_setItem, "setItem", 2));
    JS_SetPropertyStr(ctx, sessionStorage, "getItem", 
        JS_NewCFunction(ctx, js_sessionstorage_getItem, "getItem", 1));
    JS_SetPropertyStr(ctx, global_obj, "sessionStorage", sessionStorage);
}

// ============================================================================
// ShadowDOM
// ============================================================================

JSValue js_element_attachShadow(JSContext* ctx, JSValueConst this_val, 
                               int argc, JSValueConst* argv) {
    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::SHADOW_DOM_ATTACH;
        event.severity = 8;
        event.line = 0;
        event.reason = "attachShadow - DOM concealment technique";
        event.tags.insert("dom_manipulation");
        event.tags.insert("obfuscation");
        event.tags.insert("shadow_dom");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    JSValue shadowRoot = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, shadowRoot, "mode", JS_NewString(ctx, "open"));
    return shadowRoot;
}

// ============================================================================
// MutationObserver
// ============================================================================

JSValue js_mutation_observer_constructor(JSContext* ctx, JSValueConst new_target, 
                                        int argc, JSValueConst* argv) {
    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::MUTATION_OBSERVER_CREATE;
        event.severity = 7;
        event.line = 0;
        event.reason = "MutationObserver created - DOM monitoring";
        event.tags.insert("dom_manipulation");
        event.tags.insert("monitoring");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    JSValue obj = JS_NewObjectClass(ctx, 0);
    JS_SetPropertyStr(ctx, obj, "observe", 
        JS_NewCFunction(ctx, js_mutation_observer_observe, "observe", 2));
    JS_SetPropertyStr(ctx, obj, "disconnect", 
        JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, 
                                int argc, JSValueConst* argv) -> JSValue {
            return JS_UNDEFINED;
        }, "disconnect", 0));
    
    if (argc > 0) {
        JS_SetPropertyStr(ctx, obj, "_callback", JS_DupValue(ctx, argv[0]));
    }
    
    return obj;
}

JSValue js_mutation_observer_observe(JSContext* ctx, JSValueConst this_val, 
                                    int argc, JSValueConst* argv) {
    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::MUTATION_OBSERVER_OBSERVE;
        event.severity = 7;
        event.line = 0;
        event.reason = "MutationObserver.observe - tracking DOM changes";
        event.tags.insert("dom_manipulation");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }
    
    return JS_UNDEFINED;
}

// ============================================================================
// SessionStorage
// ============================================================================

JSValue js_sessionstorage_setItem(JSContext* ctx, JSValueConst this_val, 
                                 int argc, JSValueConst* argv) {
    if (argc < 2) return JS_UNDEFINED;

    const char* key = JS_ToCString(ctx, argv[0]);
    const char* value = JS_ToCString(ctx, argv[1]);
    
    std::string key_str = key ? key : "";
    std::string val_str = value ? value : "";

    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::SESSION_STORAGE_SET;
        event.line = 0;
        event.reason = "sessionStorage.setItem - storing session data";
        
        if (SensitiveKeywordDetector::containsSensitiveKeyword(val_str)) {
            event.severity = 9;
            event.reason += " (SENSITIVE DATA)";
            event.tags.insert("data_theft");
        } else {
            event.severity = 6;
        }
        
        event.features["key"] = key_str;
        event.features["value"] = val_str.length() > 200 ? 
            val_str.substr(0, 200) + "..." : val_str;
        event.tags.insert("storage");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }

    if (key) JS_FreeCString(ctx, key);
    if (value) JS_FreeCString(ctx, value);
    
    return JS_UNDEFINED;
}

JSValue js_sessionstorage_getItem(JSContext* ctx, JSValueConst this_val, 
                                 int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NULL;
    
    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        HookEvent event;
        event.hookType = HookType::SESSION_STORAGE_GET;
        event.severity = 5;
        event.line = 0;
        event.reason = "sessionStorage.getItem - reading session data";
        event.tags.insert("storage");

        a_ctx->dynamicAnalyzer->recordEvent(event);
    }
    
    return JS_NULL;
}

} // namespace MediumPriorityAPIs
