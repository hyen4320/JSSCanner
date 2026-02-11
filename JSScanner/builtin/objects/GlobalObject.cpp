#include "pch.h"
#include "GlobalObject.h"
#include "../helpers/Base64Utils.h"
#include "../helpers/JSValueConverter.h"
#include "../../model/Detection.h"
#include "../../model/JsValueVariant.h"
#include "../../core/DynamicAnalyzer.h"
#include "../../core/ChainTrackerManager.h"
#include "../../core/DynamicStringTracker.h"
#include "../../core/JSAnalyzer.h"


namespace GlobalObject {
    static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
        return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
    }

    JSValue js_print(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        for (int i = 0; i < argc; i++) {
            const char* str = JS_ToCString(ctx, argv[i]);
            if (str) {
                JS_FreeCString(ctx, str);
            }
        }
        return JS_UNDEFINED;
    }

    JSValue js_eval_hook(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) {
            return JS_UNDEFINED;
        }

        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        
        // 함수 호출 카운터 증가
        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->incrementFunctionCallCount();
        }

        bool isString = JS_IsString(argv[0]);
        std::string evalCode;
        if (isString) {
            const char* str = JS_ToCString(ctx, argv[0]);
            if (str) {
                evalCode = str;
                JS_FreeCString(ctx, str);
            }
        } else {
            evalCode = JSValueConverter::toString(ctx, argv[0]);
        }

        if (a_ctx && a_ctx->findings) {
            a_ctx->findings->push_back({0, evalCode, "eval_call_detected"});
        }

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::FUNCTION_CALL, "eval", {JsValue(evalCode)}, JsValue(std::monostate()), {}, 10});
        }

        if (a_ctx && a_ctx->chainTrackerManager) {
            a_ctx->chainTrackerManager->trackFunctionCall("eval", {JsValue(evalCode)}, JsValue(std::monostate()));
        }

        if (!isString) {
            return JS_DupValue(ctx, argv[0]);
        }

        JSValue result = JS_Eval(ctx, evalCode.c_str(), evalCode.length(), "<eval>", JS_EVAL_TYPE_GLOBAL);
        if (JS_IsException(result)) {
            JSValue exception = JS_GetException(ctx);
            if (a_ctx && a_ctx->findings) {
                std::string errorMessage = JSValueConverter::toString(ctx, exception);
                if (!errorMessage.empty()) {
                    a_ctx->findings->push_back({0, errorMessage, "eval_runtime_error"});
                }
            }
            return JS_Throw(ctx, exception);
        }

        return result;
    }

    JSValue js_atob(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        
        // 함수 호출 카운터 증가
        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->incrementFunctionCallCount();
        }
        
        if (argc < 1) return JS_NewString(ctx, "");

        const char* encoded_str_cstr = JS_ToCString(ctx, argv[0]);
        if (!encoded_str_cstr) return JS_NewString(ctx, "");

        std::string encoded_str = encoded_str_cstr;
        JS_FreeCString(ctx, encoded_str_cstr);

        std::string decoded_string = Base64Utils::decode(encoded_str);

        // 🔥 호출 횟수 제한 체크
        if (a_ctx) {
            a_ctx->functionCallCounts["atob"]++;

            int callCount = a_ctx->functionCallCounts["atob"];

            // 제한 초과 시 경고
            if (callCount > JSAnalyzerContext::MAX_FUNCTION_CALLS) {
                if (callCount == JSAnalyzerContext::MAX_FUNCTION_CALLS + 1) {
                    core::Log_Warn("JS Scanner - atob exceeded %s" ,std::to_string(JSAnalyzerContext::MAX_FUNCTION_CALLS) +
                                 " calls - further calls will be ignored to prevent DoS");

                    if (a_ctx->dynamicAnalyzer) {
                        a_ctx->dynamicAnalyzer->recordEvent({
                            HookType::CRYPTO_OPERATION,
                            "atob",
                            {JsValue("[LIMIT_EXCEEDED]")},
                            JsValue("Analysis limit exceeded - function called too many times"),
                            {},
                            9
                        });
                    }
                    a_ctx->analysisLimitExceeded = true;
                }
                return JS_NewString(ctx, decoded_string.c_str());
            }
        }

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::CRYPTO_OPERATION, "atob", {JsValue(encoded_str)}, JsValue(decoded_string), {}, 6});
        }

        if (a_ctx && a_ctx->chainTrackerManager) {
            a_ctx->chainTrackerManager->trackFunctionCall("atob", {JsValue(encoded_str)}, JsValue(decoded_string));
        }

        if (a_ctx && a_ctx->dynamicStringTracker) {
            a_ctx->dynamicStringTracker->trackString("_atob_result", decoded_string);
        }

        return JS_NewString(ctx, decoded_string.c_str());
    }

    // 🔥 setTimeout 재귀 깊이 제어
    static thread_local int g_setTimeout_depth = 0;
    static const int MAX_SETTIMEOUT_DEPTH = 100; // 최대 100회 재귀

    JSValue js_setTimeout(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (argc < 1) return JS_NewInt32(ctx, 0);

        // 🔥 재귀 깊이 체크
        if (g_setTimeout_depth >= MAX_SETTIMEOUT_DEPTH) {
            core::Log_Warn("[GlobalObject] setTimeout recursion limit reached: %d", g_setTimeout_depth);
            if (a_ctx && a_ctx->findings) {
                a_ctx->findings->push_back({
                    8, 
                    "Excessive setTimeout recursion detected (limit: " + std::to_string(MAX_SETTIMEOUT_DEPTH) + ")",
                    "settimeout_recursion_limit"
                });
            }
            return JS_NewInt32(ctx, 0);
        }

        JSValueConst funcOrCode = argv[0];

        // 🔥 재귀 깊이 증가
        g_setTimeout_depth++;

        if (JS_IsFunction(ctx, funcOrCode)) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, funcOrCode, global_obj, 0, NULL);
            
            // 🔥 예외 처리 수정 - Double-Free 방지
            if (JS_IsException(ret)) {
                // 예외 발생 시 ret은 JS_EXCEPTION으로 자동 설정됨
                // exception 객체만 가져와서 해제
                JSValue ex = JS_GetException(ctx);
                JS_FreeValue(ctx, ex);
                // ret은 해제하지 않음 (JS_EXCEPTION은 특수 값)
            } else {
                // 정상 반환값만 해제
                JS_FreeValue(ctx, ret);
            }
            
            JS_FreeValue(ctx, global_obj);
        }
        else if (JS_IsString(funcOrCode)) {
            const char* code_str = JS_ToCString(ctx, funcOrCode);
            if (code_str) {
                js_eval_hook(ctx, this_val, 1, &funcOrCode);
                JS_FreeCString(ctx, code_str);
            }
        }

        // 🔥 재귀 깊이 감소
        g_setTimeout_depth--;

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::FUNCTION_CALL, "setTimeout", {}, JsValue(std::monostate()), {}, 4});
        }
        
        if (a_ctx && a_ctx->chainTrackerManager) {
            a_ctx->chainTrackerManager->trackFunctionCall("setTimeout", {}, JsValue(std::monostate()));
        }
        
        return JS_NewInt32(ctx, 1);
    }

    // 🔥 setInterval 재귀 깊이 제어 (setTimeout과 동일)
    static thread_local int g_setInterval_depth = 0;
    static const int MAX_SETINTERVAL_DEPTH = 100;

    JSValue js_setInterval(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (argc < 1) return JS_NewInt32(ctx, 0);

        // 🔥 재귀 깊이 체크
        if (g_setInterval_depth >= MAX_SETINTERVAL_DEPTH) {
            core::Log_Warn("[GlobalObject] setInterval recursion limit reached: %d", g_setInterval_depth);
            if (a_ctx && a_ctx->findings) {
                a_ctx->findings->push_back({
                    8,
                    "Excessive setInterval recursion detected (limit: " + std::to_string(MAX_SETINTERVAL_DEPTH) + ")",
                    "setinterval_recursion_limit"
                });
            }
            return JS_NewInt32(ctx, 0);
        }

        JSValueConst funcOrCode = argv[0];

        // 🔥 재귀 깊이 증가
        g_setInterval_depth++;

        // 함수인 경우 → 1회 즉시 실행 (반복 실행 방지)
        if (JS_IsFunction(ctx, funcOrCode)) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, funcOrCode, global_obj, 0, NULL);
            
            // 🔥 예외 처리 수정 - Double-Free 방지
            if (JS_IsException(ret)) {
                // 예외 발생 시 ret은 JS_EXCEPTION으로 자동 설정됨
                JSValue ex = JS_GetException(ctx);
                JS_FreeValue(ctx, ex);
                // ret은 해제하지 않음 (JS_EXCEPTION은 특수 값)
            } else {
                // 정상 반환값만 해제
                JS_FreeValue(ctx, ret);
            }
            
            JS_FreeValue(ctx, global_obj);
        }
        // 문자열 코드인 경우 → 1회 즉시 eval
        else if (JS_IsString(funcOrCode)) {
            const char* code_str = JS_ToCString(ctx, funcOrCode);
            if (code_str) {
                js_eval_hook(ctx, this_val, 1, &funcOrCode);
                JS_FreeCString(ctx, code_str);
            }
        }

        // 🔥 재귀 깊이 감소
        g_setInterval_depth--;

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::FUNCTION_CALL, "setInterval", {}, JsValue(std::monostate()), {}, 4});
        }

        if (a_ctx && a_ctx->chainTrackerManager) {
            a_ctx->chainTrackerManager->trackFunctionCall("setInterval", {}, JsValue(std::monostate()));
        }

        return JS_NewInt32(ctx, 2);
    }

    JSValue js_clearTimeout(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        // Mock 함수: 타이머가 이미 즉시 실행되었으므로 취소할 것이 없음
        // 에러 방지를 위해 존재만 함

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::FUNCTION_CALL, "clearTimeout", {}, JsValue(std::monostate()), {}, 2});
        }

        if (a_ctx && a_ctx->chainTrackerManager) {
            a_ctx->chainTrackerManager->trackFunctionCall("clearTimeout", {}, JsValue(std::monostate()));
        }

        return JS_UNDEFINED;
    }

    JSValue js_clearInterval(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        // Mock 함수: 반복 타이머가 없으므로 취소할 것이 없음
        // 에러 방지를 위해 존재만 함

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::FUNCTION_CALL, "clearInterval", {}, JsValue(std::monostate()), {}, 2});
        }

        if (a_ctx && a_ctx->chainTrackerManager) {
            a_ctx->chainTrackerManager->trackFunctionCall("clearInterval", {}, JsValue(std::monostate()));
        }

        return JS_UNDEFINED;
    }

    // Helper function for URL encoding
    std::string urlEncode(const std::string& str, bool component) {
        std::ostringstream escaped;
        escaped.fill('0');
        escaped << std::hex;

        for (char c : str) {
            // Component mode: encode everything except: A-Z a-z 0-9 - _ . ! ~ * ' ( )
            // URI mode: also preserve: ; , / ? : @ & = + $ #
            if (std::isalnum(static_cast<unsigned char>(c)) || 
                c == '-' || c == '_' || c == '.' || c == '!' || 
                c == '~' || c == '*' || c == '\'' || c == '(' || c == ')') {
                escaped << c;
            } else if (!component && (c == ';' || c == ',' || c == '/' || c == '?' || 
                       c == ':' || c == '@' || c == '&' || c == '=' || 
                       c == '+' || c == '$' || c == '#')) {
                escaped << c;
            } else {
                escaped << std::uppercase;
                escaped << '%' << std::setw(2) << int(static_cast<unsigned char>(c));
                escaped << std::nouppercase;
            }
        }

        return escaped.str();
    }

    // Helper function for URL decoding
    std::string urlDecode(const std::string& str) {
        std::string result;
        for (size_t i = 0; i < str.length(); i++) {
            if (str[i] == '%' && i + 2 < str.length()) {
                try {
                    int value = std::stoi(str.substr(i + 1, 2), nullptr, 16);
                    result += static_cast<char>(value);
                    i += 2;
                } catch (...) {
                    result += str[i];
                }
            } else if (str[i] == '+') {
                result += ' ';
            } else {
                result += str[i];
            }
        }
        return result;
    }

    JSValue js_escape(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (argc < 1) return JS_NewString(ctx, "");
        
        const char* input_cstr = JS_ToCString(ctx, argv[0]);
        if (!input_cstr) return JS_NewString(ctx, "");
        
        std::string input_str = input_cstr;
        JS_FreeCString(ctx, input_cstr);

        // Simple escape implementation (encode special chars as %XX)
        std::string encoded_string = urlEncode(input_str, false);

        // Taint tracking
        if (a_ctx && a_ctx->chainTrackerManager) {
            TaintTracker* taintTracker = a_ctx->chainTrackerManager->getTaintTracker();
            TaintedValue* inputTaint = taintTracker->findTaintByValue(JsValue(input_str));
            
            if (inputTaint) {
                taintTracker->propagateTaint(inputTaint, JsValue(encoded_string), "escape");
            } else {
                taintTracker->createTaintedValue(JsValue(encoded_string), "escape", 5, "URL-escaped data");
            }
            
            a_ctx->chainTrackerManager->trackFunctionCall("escape", {JsValue(input_str)}, JsValue(encoded_string));
        }

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::CRYPTO_OPERATION, "escape", {JsValue(input_str)}, JsValue(encoded_string), {}, 5});
        }

        return JS_NewString(ctx, encoded_string.c_str());
    }

    JSValue js_unescape(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (argc < 1) return JS_NewString(ctx, "");
        
        const char* encoded_cstr = JS_ToCString(ctx, argv[0]);
        if (!encoded_cstr) return JS_NewString(ctx, "");
        
        std::string encoded_str = encoded_cstr;
        JS_FreeCString(ctx, encoded_cstr);

        std::string decoded_string = urlDecode(encoded_str);

        // Taint tracking
        if (a_ctx && a_ctx->chainTrackerManager) {
            TaintTracker* taintTracker = a_ctx->chainTrackerManager->getTaintTracker();
            TaintedValue* inputTaint = taintTracker->findTaintByValue(JsValue(encoded_str));
            
            if (inputTaint) {
                taintTracker->propagateTaint(inputTaint, JsValue(decoded_string), "unescape");
            } else {
                taintTracker->createTaintedValue(JsValue(decoded_string), "unescape", 6, "URL-unescaped data");
            }
            
            a_ctx->chainTrackerManager->trackFunctionCall("unescape", {JsValue(encoded_str)}, JsValue(decoded_string));
        }

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::CRYPTO_OPERATION, "unescape", {JsValue(encoded_str)}, JsValue(decoded_string), {}, 6});
        }

        return JS_NewString(ctx, decoded_string.c_str());
    }

    JSValue js_encodeURI(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (argc < 1) return JS_NewString(ctx, "");
        
        const char* input_cstr = JS_ToCString(ctx, argv[0]);
        if (!input_cstr) return JS_NewString(ctx, "");
        
        std::string input_str = input_cstr;
        JS_FreeCString(ctx, input_cstr);

        std::string encoded_string = urlEncode(input_str, false);

        // Taint tracking
        if (a_ctx && a_ctx->chainTrackerManager) {
            TaintTracker* taintTracker = a_ctx->chainTrackerManager->getTaintTracker();
            TaintedValue* inputTaint = taintTracker->findTaintByValue(JsValue(input_str));
            
            if (inputTaint) {
                taintTracker->propagateTaint(inputTaint, JsValue(encoded_string), "encodeURI");
            } else {
                taintTracker->createTaintedValue(JsValue(encoded_string), "encodeURI", 5, "URI-encoded data");
            }
            
            a_ctx->chainTrackerManager->trackFunctionCall("encodeURI", {JsValue(input_str)}, JsValue(encoded_string));
        }

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::CRYPTO_OPERATION, "encodeURI", {JsValue(input_str)}, JsValue(encoded_string), {}, 5});
        }

        return JS_NewString(ctx, encoded_string.c_str());
    }

    JSValue js_decodeURI(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (argc < 1) return JS_NewString(ctx, "");
        
        const char* encoded_cstr = JS_ToCString(ctx, argv[0]);
        if (!encoded_cstr) return JS_NewString(ctx, "");
        
        std::string encoded_str = encoded_cstr;
        JS_FreeCString(ctx, encoded_cstr);

        std::string decoded_string = urlDecode(encoded_str);

        // Taint tracking
        if (a_ctx && a_ctx->chainTrackerManager) {
            TaintTracker* taintTracker = a_ctx->chainTrackerManager->getTaintTracker();
            TaintedValue* inputTaint = taintTracker->findTaintByValue(JsValue(encoded_str));
            
            if (inputTaint) {
                taintTracker->propagateTaint(inputTaint, JsValue(decoded_string), "decodeURI");
            } else {
                taintTracker->createTaintedValue(JsValue(decoded_string), "decodeURI", 6, "URI-decoded data");
            }
            
            a_ctx->chainTrackerManager->trackFunctionCall("decodeURI", {JsValue(encoded_str)}, JsValue(decoded_string));
        }

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::CRYPTO_OPERATION, "decodeURI", {JsValue(encoded_str)}, JsValue(decoded_string), {}, 6});
        }

        return JS_NewString(ctx, decoded_string.c_str());
    }

    JSValue js_encodeURIComponent(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (argc < 1) return JS_NewString(ctx, "");
        
        const char* input_cstr = JS_ToCString(ctx, argv[0]);
        if (!input_cstr) return JS_NewString(ctx, "");
        
        std::string input_str = input_cstr;
        JS_FreeCString(ctx, input_cstr);

        std::string encoded_string = urlEncode(input_str, true);

        // Taint tracking
        if (a_ctx && a_ctx->chainTrackerManager) {
            TaintTracker* taintTracker = a_ctx->chainTrackerManager->getTaintTracker();
            TaintedValue* inputTaint = taintTracker->findTaintByValue(JsValue(input_str));
            
            if (inputTaint) {
                taintTracker->propagateTaint(inputTaint, JsValue(encoded_string), "encodeURIComponent");
            } else {
                taintTracker->createTaintedValue(JsValue(encoded_string), "encodeURIComponent", 5, "URI component encoded");
            }
            
            a_ctx->chainTrackerManager->trackFunctionCall("encodeURIComponent", {JsValue(input_str)}, JsValue(encoded_string));
        }

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::CRYPTO_OPERATION, "encodeURIComponent", {JsValue(input_str)}, JsValue(encoded_string), {}, 5});
        }

        return JS_NewString(ctx, encoded_string.c_str());
    }

    JSValue js_decodeURIComponent(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (argc < 1) return JS_NewString(ctx, "");
        
        const char* encoded_cstr = JS_ToCString(ctx, argv[0]);
        if (!encoded_cstr) return JS_NewString(ctx, "");
        
        std::string encoded_str = encoded_cstr;
        JS_FreeCString(ctx, encoded_cstr);

        std::string decoded_string = urlDecode(encoded_str);

        // Taint tracking
        if (a_ctx && a_ctx->chainTrackerManager) {
            TaintTracker* taintTracker = a_ctx->chainTrackerManager->getTaintTracker();
            TaintedValue* inputTaint = taintTracker->findTaintByValue(JsValue(encoded_str));
            
            if (inputTaint) {
                taintTracker->propagateTaint(inputTaint, JsValue(decoded_string), "decodeURIComponent");
            } else {
                taintTracker->createTaintedValue(JsValue(decoded_string), "decodeURIComponent", 6, "URI component decoded");
            }
            
            a_ctx->chainTrackerManager->trackFunctionCall("decodeURIComponent", {JsValue(encoded_str)}, JsValue(decoded_string));
        }

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::CRYPTO_OPERATION, "decodeURIComponent", {JsValue(encoded_str)}, JsValue(decoded_string), {}, 6});
        }

        return JS_NewString(ctx, decoded_string.c_str());
    }

    JSValue js_parseInt(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (argc < 1) return JS_NewInt32(ctx, 0);
        
        const char* str_cstr = JS_ToCString(ctx, argv[0]);
        if (!str_cstr) return JS_NewInt32(ctx, 0);
        
        std::string str = str_cstr;
        JS_FreeCString(ctx, str_cstr);

        int radix = 10;
        if (argc >= 2) {
            JS_ToInt32(ctx, &radix, argv[1]);
            if (radix < 2 || radix > 36) radix = 10;
        }

        int result = 0;
        try {
            result = std::stoi(str, nullptr, radix);
        } catch (...) {
            result = 0;
        }

        // Taint tracking - parseInt로 hex/octal 변환 시 추적
        if (a_ctx && a_ctx->chainTrackerManager && radix != 10) {
            TaintTracker* taintTracker = a_ctx->chainTrackerManager->getTaintTracker();
            TaintedValue* inputTaint = taintTracker->findTaintByValue(JsValue(str));
            
            if (inputTaint) {
                taintTracker->propagateTaint(inputTaint, JsValue(static_cast<double>(result)), "parseInt");
            } else {
                taintTracker->createTaintedValue(JsValue(static_cast<double>(result)), "parseInt", 4, "Radix conversion (base " + std::to_string(radix) + ")");
            }
            
            a_ctx->chainTrackerManager->trackFunctionCall("parseInt", {JsValue(str), JsValue(static_cast<double>(radix))}, JsValue(static_cast<double>(result)));
        }

        if (a_ctx && a_ctx->dynamicAnalyzer && radix != 10) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::CRYPTO_OPERATION, "parseInt", {JsValue(str), JsValue(static_cast<double>(radix))}, JsValue(static_cast<double>(result)), {}, 4});
        }

        return JS_NewInt32(ctx, result);
    }

    void registerGlobalFunctions(JSContext* ctx, JSValue global_obj) {
        JS_SetPropertyStr(ctx, global_obj, "print", JS_NewCFunction(ctx, js_print, "print", 1));
        JS_SetPropertyStr(ctx, global_obj, "eval", JS_NewCFunction(ctx, js_eval_hook, "eval", 1));
        JS_SetPropertyStr(ctx, global_obj, "atob", JS_NewCFunction(ctx, js_atob, "atob", 1));
        JS_SetPropertyStr(ctx, global_obj, "setTimeout", JS_NewCFunction(ctx, js_setTimeout, "setTimeout", 1));
        JS_SetPropertyStr(ctx, global_obj, "setInterval", JS_NewCFunction(ctx, js_setInterval, "setInterval", 1));
        JS_SetPropertyStr(ctx, global_obj, "clearTimeout", JS_NewCFunction(ctx, js_clearTimeout, "clearTimeout", 1));
        JS_SetPropertyStr(ctx, global_obj, "clearInterval", JS_NewCFunction(ctx, js_clearInterval, "clearInterval", 1));
    }
}
