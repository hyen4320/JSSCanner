#include "pch.h"
#include "RegExpObject.h"
#include <re2/re2.h>

namespace RegExpObject {

    struct RegExpInfo {
        std::string pattern;
        bool global = false;
        bool ignoreCase = false;
        bool multiline = false;
        
        static RegExpInfo extract(JSContext* ctx, JSValueConst regexp_obj) {
            RegExpInfo info;
            
            JSValue source_val = JS_GetPropertyStr(ctx, regexp_obj, "source");
            if (!JS_IsUndefined(source_val)) {
                const char* source_str = JS_ToCString(ctx, source_val);
                if (source_str) {
                    info.pattern = source_str;
                    JS_FreeCString(ctx, source_str);
                }
            }
            JS_FreeValue(ctx, source_val);
            
            JSValue flags_val = JS_GetPropertyStr(ctx, regexp_obj, "flags");
            if (!JS_IsUndefined(flags_val)) {
                const char* flags_str = JS_ToCString(ctx, flags_val);
                if (flags_str) {
                    std::string flags(flags_str);
                    info.global = flags.find('g') != std::string::npos;
                    info.ignoreCase = flags.find('i') != std::string::npos;
                    info.multiline = flags.find('m') != std::string::npos;
                    JS_FreeCString(ctx, flags_str);
                }
            }
            JS_FreeValue(ctx, flags_val);
            
            return info;
        }
    };

    re2::RE2::Options createRE2Options(const RegExpInfo& info) {
        re2::RE2::Options options;
        options.set_case_sensitive(!info.ignoreCase);
        options.set_one_line(!info.multiline);
        options.set_max_mem(8 << 20);
        return options;
    }

    JSValue js_regexp_exec(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) {
            return JS_NULL;
        }
        
        const char* input_str = JS_ToCString(ctx, argv[0]);
        if (!input_str) {
            return JS_ThrowTypeError(ctx, "exec() requires a string argument");
        }
        std::string input(input_str);
        JS_FreeCString(ctx, input_str);
        
        RegExpInfo info = RegExpInfo::extract(ctx, this_val);
        if (info.pattern.empty()) {
            core::Log_Warn("RegExp exec: empty pattern");
            return JS_NULL;
        }
        
        try {
            re2::RE2::Options options = createRE2Options(info);
            re2::RE2 re(info.pattern, options);
            
            if (!re.ok()) {
                core::Log_Error("RegExp exec: invalid pattern: %s (error: %s)", 
                    info.pattern.c_str(), re.error().c_str());
                return JS_NULL;
            }
            
            int num_groups = re.NumberOfCapturingGroups();
            std::vector<re2::StringPiece> matches(num_groups + 1);
            
            if (!re.Match(input, 0, input.size(), re2::RE2::UNANCHORED, 
                          matches.data(), matches.size())) {
                return JS_NULL;
            }
            
            JSValue result_array = JS_NewArray(ctx);
            
            for (size_t i = 0; i < matches.size(); ++i) {
                if (matches[i].data() != nullptr) {
                    std::string match_str(matches[i].data(), matches[i].size());
                    JS_SetPropertyUint32(ctx, result_array, i, 
                        JS_NewString(ctx, match_str.c_str()));
                } else {
                    JS_SetPropertyUint32(ctx, result_array, i, JS_UNDEFINED);
                }
            }
            
            size_t match_pos = matches[0].data() - input.data();
            JS_SetPropertyStr(ctx, result_array, "index", 
                JS_NewInt64(ctx, static_cast<int64_t>(match_pos)));
            
            JS_SetPropertyStr(ctx, result_array, "input", 
                JS_NewString(ctx, input.c_str()));
            
            return result_array;
            
        } catch (const std::exception& e) {
            core::Log_Error("RegExp exec exception: %s", e.what());
            return JS_NULL;
        }
    }

    JSValue js_regexp_test(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) {
            return JS_ThrowTypeError(ctx, "test() requires one argument");
        }

        const char* input_str = JS_ToCString(ctx, argv[0]);
        if (!input_str) {
            return JS_ThrowTypeError(ctx, "test() requires a string argument");
        }
        std::string input(input_str);
        JS_FreeCString(ctx, input_str);
        
        RegExpInfo info = RegExpInfo::extract(ctx, this_val);
        if (info.pattern.empty()) {
            return JS_NewBool(ctx, false);
        }
        
        try {
            re2::RE2::Options options = createRE2Options(info);
            re2::RE2 re(info.pattern, options);
            
            if (!re.ok()) {
                return JS_NewBool(ctx, false);
            }
            
            bool matched = re2::RE2::PartialMatch(input, re);
            return JS_NewBool(ctx, matched);
            
        } catch (const std::exception& e) {
            core::Log_Error("RegExp test exception: %s", e.what());
            return JS_NewBool(ctx, false);
        }
    }

    JSValue js_string_match(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) {
            return JS_ThrowTypeError(ctx, "match() requires one argument");
        }

        const char* str = JS_ToCString(ctx, this_val);
        if (!str) {
            return JS_ThrowTypeError(ctx, "match() requires a string");
        }

        JSValue str_val = JS_NewString(ctx, str);
        JS_FreeCString(ctx, str);

        JSValue exec_result = js_regexp_exec(ctx, argv[0], 1, &str_val);
        JS_FreeValue(ctx, str_val);

        return exec_result;
    }

    JSValue js_string_replace(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 2) {
            return JS_ThrowTypeError(ctx, "replace() requires two arguments");
        }

        const char* str = JS_ToCString(ctx, this_val);
        if (!str) {
            return JS_ThrowTypeError(ctx, "replace() requires a string");
        }
        std::string input(str);
        JS_FreeCString(ctx, str);

        const char* repl_str = JS_ToCString(ctx, argv[1]);
        if (!repl_str) {
            return JS_NewString(ctx, input.c_str());
        }
        std::string replacement(repl_str);
        JS_FreeCString(ctx, repl_str);

        RegExpInfo info = RegExpInfo::extract(ctx, argv[0]);
        if (info.pattern.empty()) {
            return JS_NewString(ctx, input.c_str());
        }

        try {
            re2::RE2::Options options = createRE2Options(info);
            re2::RE2 re(info.pattern, options);
            
            if (!re.ok()) {
                return JS_NewString(ctx, input.c_str());
            }

            std::string result = input;
            
            if (info.global) {
                re2::RE2::GlobalReplace(&result, re, replacement);
            } else {
                re2::RE2::Replace(&result, re, replacement);
            }

            return JS_NewString(ctx, result.c_str());
            
        } catch (const std::exception& e) {
            core::Log_Error("RegExp replace exception: %s", e.what());
            return JS_NewString(ctx, input.c_str());
        }
    }

    void registerRegExpMethods(JSContext* ctx, JSValue global_obj) {
        JSValue regexp_ctor = JS_GetPropertyStr(ctx, global_obj, "RegExp");
        if (JS_IsUndefined(regexp_ctor)) {
            core::Log_Warn("RegExp constructor not found");
            return;
        }

        JSValue regexp_proto = JS_GetPropertyStr(ctx, regexp_ctor, "prototype");
        if (JS_IsUndefined(regexp_proto)) {
            core::Log_Warn("RegExp.prototype not found");
            JS_FreeValue(ctx, regexp_ctor);
            return;
        }

        JS_SetPropertyStr(ctx, regexp_proto, "exec",
            JS_NewCFunction(ctx, js_regexp_exec, "exec", 1));
        
        JS_SetPropertyStr(ctx, regexp_proto, "test",
            JS_NewCFunction(ctx, js_regexp_test, "test", 1));

        JS_FreeValue(ctx, regexp_proto);
        JS_FreeValue(ctx, regexp_ctor);

        JSValue string_ctor = JS_GetPropertyStr(ctx, global_obj, "String");
        if (!JS_IsUndefined(string_ctor)) {
            JSValue string_proto = JS_GetPropertyStr(ctx, string_ctor, "prototype");
            if (!JS_IsUndefined(string_proto)) {
                JS_SetPropertyStr(ctx, string_proto, "match",
                    JS_NewCFunction(ctx, js_string_match, "match", 1));

                JS_SetPropertyStr(ctx, string_proto, "replace",
                    JS_NewCFunction(ctx, js_string_replace, "replace", 2));

                JS_FreeValue(ctx, string_proto);
            }
            JS_FreeValue(ctx, string_ctor);
        }

        core::Log_Info("RE2-based RegExp methods registered successfully");
    }

}
