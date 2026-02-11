#include "pch.h"
#include "ElementObject.h"
#include "../helpers/JSValueConverter.h"
#include "../helpers/MockHelpers.h"
#include "../../core/JSAnalyzer.h"

namespace ElementObject {
    static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
        return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
    }

    JSValue js_classList_add(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) {
            return JS_UNDEFINED;
        }
        std::string token = JSValueConverter::toString(ctx, argv[0]);
        MockHelpers::classListAddToken(ctx, JS_DupValue(ctx, this_val), token);
        return JS_UNDEFINED;
    }

    JSValue js_classList_remove(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) {
            return JS_UNDEFINED;
        }
        std::string token = JSValueConverter::toString(ctx, argv[0]);
        
        if (token.empty()) {
            return JS_UNDEFINED;
        }

        JSValue listDup = JS_DupValue(ctx, this_val);
        JSValue tokens_val = JS_GetPropertyStr(ctx, listDup, "_tokens");
        std::string current;
        if (!JS_IsUndefined(tokens_val) && !JS_IsNull(tokens_val)) {
            current = JSValueConverter::toString(ctx, tokens_val);
        }
        JS_FreeValue(ctx, tokens_val);

        std::set<std::string> tokens = MockHelpers::parseClassTokens(current);
        tokens.erase(token);
        JS_SetPropertyStr(ctx, listDup, "_tokens", JS_NewString(ctx, MockHelpers::joinClassTokens(tokens).c_str()));
        JS_FreeValue(ctx, listDup);
        return JS_UNDEFINED;
    }

    JSValue js_classList_contains(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) {
            return JS_NewBool(ctx, 0);
        }
        std::string token = JSValueConverter::toString(ctx, argv[0]);
        JSValue listDup = JS_DupValue(ctx, this_val);
        JSValue tokens_val = JS_GetPropertyStr(ctx, listDup, "_tokens");
        std::string current;
        if (!JS_IsUndefined(tokens_val) && !JS_IsNull(tokens_val)) {
            current = JSValueConverter::toString(ctx, tokens_val);
        }
        JS_FreeValue(ctx, tokens_val);
        JS_FreeValue(ctx, listDup);
        std::set<std::string> tokens = MockHelpers::parseClassTokens(current);
        return JS_NewBool(ctx, tokens.count(token) ? 1 : 0);
    }

    JSValue js_element_setAttribute(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 2) {
            return JS_UNDEFINED;
        }
        std::string name = JSValueConverter::toString(ctx, argv[0]);
        std::string value = JSValueConverter::toString(ctx, argv[1]);
        MockHelpers::setMockAttribute(ctx, JS_DupValue(ctx, this_val), name, value);
        return JS_UNDEFINED;
    }

    JSValue js_element_getAttribute(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) {
            return JS_NULL;
        }
        std::string name = JSValueConverter::toString(ctx, argv[0]);
        JSValue elementDup = JS_DupValue(ctx, this_val);
        JSValue attrs = JS_GetPropertyStr(ctx, elementDup, "__attributes");
        if (JS_IsUndefined(attrs) || JS_IsNull(attrs)) {
            JS_FreeValue(ctx, attrs);
            JS_FreeValue(ctx, elementDup);
            return JS_NULL;
        }
        JSValue value = JS_GetPropertyStr(ctx, attrs, name.c_str());
        JS_FreeValue(ctx, attrs);
        JS_FreeValue(ctx, elementDup);
        if (JS_IsUndefined(value)) {
            JS_FreeValue(ctx, value);
            return JS_NULL;
        }
        return value;
    }

    JSValue js_element_hasAttribute(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) {
            return JS_NewBool(ctx, 0);
        }
        std::string name = JSValueConverter::toString(ctx, argv[0]);
        JSValue elementDup = JS_DupValue(ctx, this_val);
        JSValue attrs = JS_GetPropertyStr(ctx, elementDup, "__attributes");
        if (JS_IsUndefined(attrs) || JS_IsNull(attrs)) {
            JS_FreeValue(ctx, attrs);
            JS_FreeValue(ctx, elementDup);
            return JS_NewBool(ctx, 0);
        }
        JSValue value = JS_GetPropertyStr(ctx, attrs, name.c_str());
        bool hasAttr = !JS_IsUndefined(value) && !JS_IsNull(value);
        JS_FreeValue(ctx, value);
        JS_FreeValue(ctx, attrs);
        JS_FreeValue(ctx, elementDup);
        return JS_NewBool(ctx, hasAttr ? 1 : 0);
    }

    JSValue js_element_removeAttribute(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) {
            return JS_UNDEFINED;
        }
        std::string name = JSValueConverter::toString(ctx, argv[0]);
        JSValue elementDup = JS_DupValue(ctx, this_val);
        JSValue attrs = JS_GetPropertyStr(ctx, elementDup, "__attributes");
        if (!JS_IsUndefined(attrs) && !JS_IsNull(attrs)) {
            JSAtom keyAtom = JS_NewAtom(ctx, name.c_str());
            JS_DeleteProperty(ctx, attrs, keyAtom, 0);
            JS_FreeAtom(ctx, keyAtom);
        }
        JS_FreeValue(ctx, attrs);
        JS_FreeValue(ctx, elementDup);
        return JS_UNDEFINED;
    }

    JSValue js_element_addEventListener(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 2 || !JS_IsFunction(ctx, argv[1])) {
            return JS_UNDEFINED;
        }

        // 재귀 깊이 체크 추가 - 무한 재귀 방지
        static thread_local int recursion_depth = 0;
        const int MAX_RECURSION_DEPTH = 100;
        
        if (recursion_depth >= MAX_RECURSION_DEPTH) {
            JS_ThrowRangeError(ctx, "Maximum event listener recursion depth exceeded");
            return JS_EXCEPTION;
        }

        std::string eventName = JSValueConverter::toString(ctx, argv[0]);
        if (eventName.empty()) {
            return JS_UNDEFINED;
        }

        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::DOM_MANIPULATION, "addEventListener", 
                {JsValue(eventName)}, JsValue(std::monostate()), {}, 0});
        }

        JSValue elementDup = JS_DupValue(ctx, this_val);
        JSValue idVal = JS_GetPropertyStr(ctx, elementDup, "id");
        std::string elementId = JSValueConverter::toString(ctx, idVal);
        JS_FreeValue(ctx, idVal);

        JSValue targetOverride = JS_UNDEFINED;
        if (eventName == "click" && elementId == "chooseForm") {
            JSValue target = MockHelpers::createMockElement(ctx, "select-factor-target");
            JSValue classList = JS_GetPropertyStr(ctx, target, "classList");
            MockHelpers::classListAddToken(ctx, classList, "select-factor");
            MockHelpers::setMockAttribute(ctx, JS_DupValue(ctx, target), "data-factor", "sms");
            targetOverride = target;
        } else if (eventName == "click" || eventName == "submit" || eventName == "input" || eventName == "keypress") {
            targetOverride = JS_DupValue(ctx, this_val);
        }

        JSValue eventObj = MockHelpers::createEventObject(ctx, this_val, eventName, targetOverride);

        // 재귀 카운터 증가
        recursion_depth++;
        
        JSValue thisDup = JS_DupValue(ctx, this_val);
        JSValueConst args_arr[1] = { eventObj };
        JSValue ret = JS_Call(ctx, argv[1], thisDup, 1, args_arr);
        
        // 재귀 카운터 감소 (항상 실행되도록)
        recursion_depth--;
        
        // 🔥 예외 처리 - Double-Free 방지
        if (JS_IsException(ret)) {
            JSValue ex = JS_GetException(ctx);
            JS_FreeValue(ctx, ex);
        } else {
            JS_FreeValue(ctx, ret);
        }
        
        JS_FreeValue(ctx, thisDup);
        JS_FreeValue(ctx, eventObj);
        JS_FreeValue(ctx, elementDup);

        return JS_UNDEFINED;
    }

    JSValue js_element_appendChild(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) return JS_NULL;
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (a_ctx && a_ctx->chainTrackerManager) {
            a_ctx->chainTrackerManager->trackFunctionCall("appendChild", {}, JsValue(std::monostate()));
        }
        return JS_DupValue(ctx, argv[0]);
    }
}
