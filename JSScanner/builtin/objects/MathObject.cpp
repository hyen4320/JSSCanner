#include "pch.h"
#include "MathObject.h"
#include "../../model/JsValueVariant.h"
#include "../../core/JSAnalyzer.h"
#include <cmath>

namespace MathObject {
    static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
        return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
    }

    JSValue js_math_generic_hook(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (!a_ctx || !a_ctx->dynamicAnalyzer) {
            return JS_UNDEFINED;
        }

        // magic 값에 따라 어떤 함수가 호출되었는지 식별
        std::string funcName = "Math.unknown";
        if (magic == 0) { funcName = "Math.random"; }
        else if (magic == 1) { funcName = "Math.floor"; }

        // 동적 분석 이벤트 기록
        std::vector<JsValue> args_vec;
        for (int i = 0; i < argc; i++) {
            double d;
            if (JS_ToFloat64(ctx, &d, argv[i]) == 0) {
                args_vec.push_back(d);
            }
        }

        a_ctx->dynamicAnalyzer->recordEvent({HookType::FUNCTION_CALL, funcName, args_vec, 
            JsValue(std::monostate()), {}, 1});

        if (a_ctx && a_ctx->chainTrackerManager) {
            a_ctx->chainTrackerManager->trackFunctionCall(funcName, args_vec, JsValue(std::monostate()));
        }

        // 실제 함수 동작 흉내
        if (funcName == "Math.random") {
            return JS_NewFloat64(ctx, 0.12345);
        }
        if (funcName == "Math.floor" && argc > 0) {
            double d;
            JS_ToFloat64(ctx, &d, argv[0]);
            return JS_NewFloat64(ctx, floor(d));
        }

        return JS_UNDEFINED;
    }

    void registerMathFunctions(JSContext* ctx, JSValue global_obj) {
        JSValue math_obj = JS_GetPropertyStr(ctx, global_obj, "Math");
        if (!JS_IsUndefined(math_obj)) {
            JS_SetPropertyStr(ctx, math_obj, "random", 
                JS_NewCFunctionMagic(ctx, js_math_generic_hook, "random", 0, JS_CFUNC_generic_magic, 0));
            
            JS_SetPropertyStr(ctx, math_obj, "floor", 
                JS_NewCFunctionMagic(ctx, js_math_generic_hook, "floor", 1, JS_CFUNC_generic_magic, 1));
            
            JS_FreeValue(ctx, math_obj);
        }
    }
}
