#include "pch.h"
#include "ArrayObject.h"
#include "../helpers/JSValueConverter.h"
#include "../../model/JsValueVariant.h"
#include "../../core/JSAnalyzer.h"

namespace ArrayObject {
    static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
        return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
    }

    JSValue js_array_join(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        std::string result_str = "";
        std::string separator = ",";

        if (argc >= 1) {
            const char* sep_str = JS_ToCString(ctx, argv[0]);
            if (sep_str) {
                separator = sep_str;
                JS_FreeCString(ctx, sep_str);
            }
        }

        JSValue len_val = JS_GetPropertyStr(ctx, this_val, "length");
        int32_t len;
        if (JS_ToInt32(ctx, &len, len_val) != 0) {
            JS_FreeValue(ctx, len_val);
            return JS_EXCEPTION;
        }
        JS_FreeValue(ctx, len_val);

        for (int i = 0; i < len; i++) {
            JSValue item = JS_GetPropertyUint32(ctx, this_val, i);
            const char* item_str = JS_ToCString(ctx, item);
            if (item_str) {
                result_str += item_str;
                JS_FreeCString(ctx, item_str);
            }
            if (i < len - 1) {
                result_str += separator;
            }
            JS_FreeValue(ctx, item);
        }

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::FUNCTION_CALL, "Array.join", {JsValue(separator)}, JsValue(result_str), {}, 2});
        }
        
        if (a_ctx && a_ctx->chainTrackerManager) {
            a_ctx->chainTrackerManager->trackFunctionCall("Array.join", {JsValue(separator)}, JsValue(result_str));
        }
        
        return JS_NewString(ctx, result_str.c_str());
    }

    JSValue js_array_push(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSValue len_val = JS_GetPropertyStr(ctx, this_val, "length");
        int32_t len;
        if (JS_ToInt32(ctx, &len, len_val) != 0) {
            JS_FreeValue(ctx, len_val);
            return JS_EXCEPTION;
        }
        JS_FreeValue(ctx, len_val);

        for (int i = 0; i < argc; i++) {
            JS_SetPropertyUint32(ctx, this_val, len + i, JS_DupValue(ctx, argv[i]));
        }

        int32_t new_len = len + argc;
        JS_SetPropertyStr(ctx, this_val, "length", JS_NewInt32(ctx, new_len));
        return JS_NewInt32(ctx, new_len);
    }

    JSValue js_array_pop(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSValue len_val = JS_GetPropertyStr(ctx, this_val, "length");
        int32_t len;
        if (JS_ToInt32(ctx, &len, len_val) != 0) {
            JS_FreeValue(ctx, len_val);
            return JS_EXCEPTION;
        }
        JS_FreeValue(ctx, len_val);

        if (len == 0) {
            return JS_UNDEFINED;
        }

        int32_t new_len = len - 1;
        JSValue last_item = JS_GetPropertyUint32(ctx, this_val, new_len);

        std::string index_str = std::to_string(new_len);
        JSAtom prop_atom = JS_NewAtom(ctx, index_str.c_str());
        JS_DeleteProperty(ctx, this_val, prop_atom, 0);
        JS_FreeAtom(ctx, prop_atom);

        JS_SetPropertyStr(ctx, this_val, "length", JS_NewInt32(ctx, new_len));

        return last_item;
    }

    JSValue js_array_slice(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSValue new_arr = JS_NewArray(ctx);

        JSValue len_val = JS_GetPropertyStr(ctx, this_val, "length");
        int32_t len;
        if (JS_ToInt32(ctx, &len, len_val) != 0) {
            JS_FreeValue(ctx, len_val);
            return JS_EXCEPTION;
        }
        JS_FreeValue(ctx, len_val);

        int32_t start = 0;
        if (argc >= 1) JS_ToInt32(ctx, &start, argv[0]);
        if (start < 0) start = (std::max)(0, len + start);

        int32_t end = len;
        if (argc >= 2) JS_ToInt32(ctx, &end, argv[1]);
        if (end < 0) end = len + end;
        end = (std::min)(len, end);

        int k = 0;
        for (int i = start; i < end; i++) {
            JSValue item = JS_GetPropertyUint32(ctx, this_val, i);
            JS_SetPropertyUint32(ctx, new_arr, k++, item);
        }
        return new_arr;
    }

    JSValue js_uint8array_from(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) {
            return JS_ThrowTypeError(ctx, "Uint8Array.from() requires at least 1 argument");
        }

        // 첫 번째 인수가 iterable인지 확인
        JSValue iterable = argv[0];
        
        // 🔍 문자열인 경우 특별 처리
        bool is_string = JS_IsString(iterable);
        const char* str_data = nullptr;
        size_t str_len = 0;
        
        if (is_string) {
            str_data = JS_ToCStringLen(ctx, &str_len, iterable);
            if (!str_data) {
                return JS_ThrowTypeError(ctx, "Cannot read string data");
            }
        }
        
        // 배열 길이 가져오기
        JSValue len_val = JS_GetPropertyStr(ctx, iterable, "length");
        int32_t len;
        if (JS_ToInt32(ctx, &len, len_val) != 0) {
            JS_FreeValue(ctx, len_val);
            if (is_string && str_data) JS_FreeCString(ctx, str_data);
            return JS_ThrowTypeError(ctx, "Invalid iterable");
        }
        JS_FreeValue(ctx, len_val);

        // Uint8Array 생성
        std::vector<uint8_t> data;
        data.reserve(len);

        // mapFn이 제공되었는지 확인 (두 번째 인수)
        bool has_map_fn = (argc >= 2 && JS_IsFunction(ctx, argv[1]));

        // 각 요소 처리
        for (int32_t i = 0; i < len; i++) {
            JSValue processed_item;
            
            // 🔍 문자열인 경우: charCode 직접 사용
            if (is_string && str_data) {
                // UTF-8 바이트 직접 사용
                uint8_t byte_val = static_cast<uint8_t>(str_data[i]);
                processed_item = JS_NewInt32(ctx, byte_val);
            }
            // 일반 iterable인 경우
            else {
                JSValue item = JS_GetPropertyUint32(ctx, iterable, i);
                processed_item = item;

                // mapFn이 있으면 호출
                if (has_map_fn) {
                    JSValue args[2] = { item, JS_NewInt32(ctx, i) };
                    processed_item = JS_Call(ctx, argv[1], JS_UNDEFINED, 2, args);
                    JS_FreeValue(ctx, args[1]);
                    if (JS_IsException(processed_item)) {
                        JS_FreeValue(ctx, item);
                        if (is_string && str_data) JS_FreeCString(ctx, str_data);
                        return JS_EXCEPTION;
                    }
                    JS_FreeValue(ctx, item);
                }
            }

            // 숫자로 변환
            int32_t num;
            if (JS_ToInt32(ctx, &num, processed_item) != 0) {
                JS_FreeValue(ctx, processed_item);
                if (is_string && str_data) JS_FreeCString(ctx, str_data);
                return JS_ThrowTypeError(ctx, "Cannot convert to number");
            }

            // 0-255 범위로 제한
            data.push_back(static_cast<uint8_t>(num & 0xFF));

            JS_FreeValue(ctx, processed_item);
        }
        
        // 문자열 메모리 해제
        if (is_string && str_data) {
            JS_FreeCString(ctx, str_data);
        }

        // 힙에 메모리 할당
        uint8_t* buffer = (uint8_t*)js_malloc(ctx, len);
        if (!buffer) {
            return JS_ThrowOutOfMemory(ctx);
        }
        
        // 데이터 복사
        std::copy(data.begin(), data.end(), buffer);

        // Uint8Array 생성 및 반환 (QuickJS가 메모리를 관리하도록 free_func를 js_free로 설정)
        return JS_NewUint8Array(ctx, buffer, len, 
            [](JSRuntime *rt, void *opaque, void *ptr) { js_free_rt(rt, ptr); }, 
            nullptr, false);
    }

    void registerArrayFunctions(JSContext* ctx, JSValue global_obj) {
        JSValue array_constructor = JS_GetPropertyStr(ctx, global_obj, "Array");
        JSValue array_proto = JS_GetPropertyStr(ctx, array_constructor, "prototype");
        
        JS_SetPropertyStr(ctx, array_proto, "join", JS_NewCFunction(ctx, js_array_join, "join", 1));
        JS_SetPropertyStr(ctx, array_proto, "push", JS_NewCFunction(ctx, js_array_push, "push", 1));
        JS_SetPropertyStr(ctx, array_proto, "pop", JS_NewCFunction(ctx, js_array_pop, "pop", 0));
        JS_SetPropertyStr(ctx, array_proto, "slice", JS_NewCFunction(ctx, js_array_slice, "slice", 2));
        
        JS_FreeValue(ctx, array_constructor);
        JS_FreeValue(ctx, array_proto);
        
        // Uint8Array.from 추가
        JSValue uint8array_constructor = JS_GetPropertyStr(ctx, global_obj, "Uint8Array");
        if (!JS_IsUndefined(uint8array_constructor)) {
            JS_SetPropertyStr(ctx, uint8array_constructor, "from", 
                JS_NewCFunction(ctx, js_uint8array_from, "from", 1));
            JS_FreeValue(ctx, uint8array_constructor);
        }
    }
}
