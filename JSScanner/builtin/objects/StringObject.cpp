#include "pch.h"
#include "StringObject.h"
#include "../../model/JsValueVariant.h"
#include "../../core/JSAnalyzer.h"

namespace StringObject {
    static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
        return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
    }

    JSValue js_string_fromCharCode(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        std::string result = "";
        std::vector<JsValue> args_vec;

        for (int i = 0; i < argc; i++) {
            int32_t code;
            if (JS_ToInt32(ctx, &code, argv[i]) != 0) {
                continue;
            }
            result += static_cast<char>(code);
            args_vec.push_back(static_cast<double>(code));
        }

        // 🔥 호출 횟수 제한 체크
        if (a_ctx) {
            a_ctx->functionCallCounts["String.fromCharCode"]++;

            int callCount = a_ctx->functionCallCounts["String.fromCharCode"];

            // 제한 초과 시 첫 번째 경고만 기록하고 이후는 무시
            if (callCount > JSAnalyzerContext::MAX_FUNCTION_CALLS) {
                if (callCount == JSAnalyzerContext::MAX_FUNCTION_CALLS + 1) {
                    core::Log_Warn("String.fromCharCode exceeded $s" ,std::to_string(JSAnalyzerContext::MAX_FUNCTION_CALLS) +
                                 " calls - further calls will be ignored to prevent DoS");

                    // 경고 이벤트만 한 번 기록
                    if (a_ctx->dynamicAnalyzer) {
                        a_ctx->dynamicAnalyzer->recordEvent({
                            HookType::FUNCTION_CALL,
                            "String.fromCharCode",
                            {JsValue("[LIMIT_EXCEEDED]")},
                            JsValue("Analysis limit exceeded - function called too many times"),
                            {},
                            9  // 높은 severity
                        });
                    }
                    a_ctx->analysisLimitExceeded = true;
                }
                // 제한 초과 후에는 추적하지 않음 (성능 향상)
                return JS_NewString(ctx, result.c_str());
            }
        }

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::FUNCTION_CALL, "String.fromCharCode", args_vec, JsValue(result), {}, 3});
        }

        if (a_ctx && a_ctx->chainTrackerManager) {
            a_ctx->chainTrackerManager->trackFunctionCall("String.fromCharCode", args_vec, JsValue(result));
        }

        if (a_ctx && a_ctx->dynamicStringTracker) {
            a_ctx->dynamicStringTracker->trackString("_fromCharCode_result", result);
        }

        return JS_NewString(ctx, result.c_str());
    }

    void registerStringFunctions(JSContext* ctx, JSValue global_obj) {
        JSValue string_constructor = JS_GetPropertyStr(ctx, global_obj, "String");
        JS_SetPropertyStr(ctx, string_constructor, "fromCharCode", 
            JS_NewCFunction(ctx, js_string_fromCharCode, "fromCharCode", 1));
        JS_SetPropertyStr(ctx, global_obj, "String", string_constructor);
    }
}
