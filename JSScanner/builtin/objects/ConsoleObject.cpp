#include "pch.h"
#include "ConsoleObject.h"
#include "../helpers/JSValueConverter.h"
#include "../helpers/SensitiveKeywordDetector.h"
#include "../../core/JSAnalyzer.h"

namespace ConsoleObject {

    static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
        return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
    }

    static bool containsEvalPattern(const std::string& text) {
        return text.find("eval(") != std::string::npos || 
               text.find("Function(") != std::string::npos ||
               text.find("new Function") != std::string::npos;
    }

    static bool isBase64Encoded(const std::string& text) {
        if (text.length() < 16) return false;
        RE2 base64_pattern("^[A-Za-z0-9+/]+=*$");
        return RE2::FullMatch(text, base64_pattern);
    }

    JSValue js_console_log(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        (void)this_val;
        
        std::string combined_message;
        std::vector<JsValue> args_vec;
        
        for (int i = 0; i < argc; ++i) {
            std::string str = JSValueConverter::toString(ctx, argv[i]);
            if (!combined_message.empty()) {
                combined_message += " ";
            }
            combined_message += str;
            args_vec.push_back(JsValue(str));
        }

        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (a_ctx && a_ctx->dynamicAnalyzer && !combined_message.empty()) {
            std::map<std::string, JsValue> metadata;
            metadata["message"] = JsValue(combined_message.length() > 200 ? 
                combined_message.substr(0, 200) + "..." : combined_message);
            metadata["arg_count"] = JsValue(static_cast<double>(argc));
            
            int severity = 3;
            std::string matched_keywords;
            
            if (SensitiveKeywordDetector::detect(combined_message, matched_keywords)) {
                severity = 8;
                metadata["keywords"] = JsValue(matched_keywords);
                metadata["reason"] = JsValue("SENSITIVE DATA logged");
            } else if (containsEvalPattern(combined_message)) {
                severity = 7;
                metadata["reason"] = JsValue("eval/Function code logged");
            } else if (isBase64Encoded(combined_message)) {
                severity = 6;
                metadata["reason"] = JsValue("Base64 encoded data");
            }
            
            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::CONSOLE_LOG,
                "console.log",
                args_vec,
                JsValue(),
                metadata,
                severity
            });
        }
        
        return JS_UNDEFINED;
    }

    JSValue js_console_warn(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        (void)this_val;
        
        std::string combined_message;
        std::vector<JsValue> args_vec;
        
        for (int i = 0; i < argc; ++i) {
            std::string str = JSValueConverter::toString(ctx, argv[i]);
            if (!combined_message.empty()) {
                combined_message += " ";
            }
            combined_message += str;
            args_vec.push_back(JsValue(str));
        }

        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (a_ctx && a_ctx->dynamicAnalyzer && !combined_message.empty()) {
            std::map<std::string, JsValue> metadata;
            metadata["message"] = JsValue(combined_message.length() > 200 ? 
                combined_message.substr(0, 200) + "..." : combined_message);
            
            int severity = 4;
            std::string matched_keywords;
            
            if (SensitiveKeywordDetector::detect(combined_message, matched_keywords)) {
                severity = 8;
                metadata["keywords"] = JsValue(matched_keywords);
                metadata["reason"] = JsValue("SENSITIVE DATA in warning");
            }
            
            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::CONSOLE_WARN,
                "console.warn",
                args_vec,
                JsValue(),
                metadata,
                severity
            });
        }
        
        return JS_UNDEFINED;
    }

    JSValue js_console_error(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        (void)this_val;
        
        std::string combined_message;
        std::vector<JsValue> args_vec;
        
        for (int i = 0; i < argc; ++i) {
            std::string str = JSValueConverter::toString(ctx, argv[i]);
            if (!combined_message.empty()) {
                combined_message += " ";
            }
            combined_message += str;
            args_vec.push_back(JsValue(str));
        }

        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (a_ctx && a_ctx->dynamicAnalyzer && !combined_message.empty()) {
            std::map<std::string, JsValue> metadata;
            metadata["message"] = JsValue(combined_message.length() > 200 ? 
                combined_message.substr(0, 200) + "..." : combined_message);
            
            int severity = 5;
            std::string matched_keywords;
            
            if (SensitiveKeywordDetector::detect(combined_message, matched_keywords)) {
                severity = 9;
                metadata["keywords"] = JsValue(matched_keywords);
                metadata["reason"] = JsValue("SENSITIVE DATA in error");
            } else if (combined_message.find("stack") != std::string::npos ||
                       combined_message.find("trace") != std::string::npos) {
                severity = 6;
                metadata["reason"] = JsValue("Stack trace disclosure");
            }
            
            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::CONSOLE_ERROR,
                "console.error",
                args_vec,
                JsValue(),
                metadata,
                severity
            });
        }
        
        return JS_UNDEFINED;
    }

    void registerConsoleObject(JSContext* ctx, JSValue global_obj) {
        JSValue console_obj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, console_obj, "log", JS_NewCFunction(ctx, js_console_log, "log", 1));
        JS_SetPropertyStr(ctx, console_obj, "warn", JS_NewCFunction(ctx, js_console_warn, "warn", 1));
        JS_SetPropertyStr(ctx, console_obj, "error", JS_NewCFunction(ctx, js_console_error, "error", 1));
        JS_SetPropertyStr(ctx, global_obj, "console", console_obj);
    }
}
