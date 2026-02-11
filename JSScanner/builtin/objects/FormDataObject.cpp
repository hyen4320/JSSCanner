#include "pch.h"
#include "FormDataObject.h"
#include "../helpers/JSValueConverter.h"
#include "../../core/JSAnalyzer.h"

namespace FormDataObject {
    static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
        return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
    }

    // FormData 생성자
    JSValue js_formdata_constructor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv) {
        JSValue obj = JS_NewObjectClass(ctx, 0);
        if (JS_IsException(obj)) {
            return obj;
        }

        // 내부 데이터 저장용 객체
        JSValue data = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, obj, "__formdata__", data);

        // form 요소가 전달된 경우 자동으로 form 데이터 추출
        if (argc > 0 && JS_IsObject(argv[0])) {
            JSValue elements = JS_GetPropertyStr(ctx, argv[0], "elements");
            if (JS_IsObject(elements)) {
                // elements는 HTMLFormElement의 input들
                JSValue lengthVal = JS_GetPropertyStr(ctx, elements, "length");
                int32_t length = 0;
                JS_ToInt32(ctx, &length, lengthVal);
                JS_FreeValue(ctx, lengthVal);

                for (int32_t i = 0; i < length; i++) {
                    JSValue element = JS_GetPropertyUint32(ctx, elements, i);
                    if (!JS_IsUndefined(element) && !JS_IsNull(element)) {
                        JSValue nameVal = JS_GetPropertyStr(ctx, element, "name");
                        JSValue valueVal = JS_GetPropertyStr(ctx, element, "value");

                        std::string name = JSValueConverter::toString(ctx, nameVal);
                        std::string value = JSValueConverter::toString(ctx, valueVal);

                        if (!name.empty()) {
                            JS_SetPropertyStr(ctx, data, name.c_str(), JS_NewString(ctx, value.c_str()));
                        }

                        JS_FreeValue(ctx, nameVal);
                        JS_FreeValue(ctx, valueVal);
                    }
                    JS_FreeValue(ctx, element);
                }
            }
            JS_FreeValue(ctx, elements);
        }

        return obj;
    }

    // FormData.prototype.append(name, value)
    JSValue js_formdata_append(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 2) return JS_UNDEFINED;

        std::string name = JSValueConverter::toString(ctx, argv[0]);
        std::string value = JSValueConverter::toString(ctx, argv[1]);

        JSValue data = JS_GetPropertyStr(ctx, this_val, "__formdata__");
        if (!JS_IsUndefined(data) && !JS_IsNull(data)) {
            // 기존 값이 있으면 배열로 변환 (여러 값 지원)
            JSValue existingVal = JS_GetPropertyStr(ctx, data, name.c_str());
            if (!JS_IsUndefined(existingVal) && !JS_IsNull(existingVal)) {
                // 이미 배열이면 추가
                if (JS_IsArray(existingVal) > 0) {
                    JSValue lengthVal = JS_GetPropertyStr(ctx, existingVal, "length");
                    int32_t length = 0;
                    JS_ToInt32(ctx, &length, lengthVal);
                    JS_FreeValue(ctx, lengthVal);
                    JS_SetPropertyUint32(ctx, existingVal, length, JS_NewString(ctx, value.c_str()));
                } else {
                    // 배열로 변환
                    JSValue arr = JS_NewArray(ctx);
                    JS_SetPropertyUint32(ctx, arr, 0, existingVal);
                    JS_SetPropertyUint32(ctx, arr, 1, JS_NewString(ctx, value.c_str()));
                    JS_SetPropertyStr(ctx, data, name.c_str(), arr);
                }
            } else {
                JS_SetPropertyStr(ctx, data, name.c_str(), JS_NewString(ctx, value.c_str()));
            }
            JS_FreeValue(ctx, existingVal);
        }
        JS_FreeValue(ctx, data);

        return JS_UNDEFINED;
    }

    // FormData.prototype.get(name)
    JSValue js_formdata_get(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) return JS_NULL;

        std::string name = JSValueConverter::toString(ctx, argv[0]);
        JSValue data = JS_GetPropertyStr(ctx, this_val, "__formdata__");
        if (!JS_IsUndefined(data) && !JS_IsNull(data)) {
            JSValue val = JS_GetPropertyStr(ctx, data, name.c_str());
            JS_FreeValue(ctx, data);
            // 배열이면 첫 번째 값 반환
            if (JS_IsArray(val) > 0) {
                JSValue first = JS_GetPropertyUint32(ctx, val, 0);
                JS_FreeValue(ctx, val);
                return first;
            }
            return val;
        }
        JS_FreeValue(ctx, data);
        return JS_NULL;
    }

    // FormData.prototype.has(name)
    JSValue js_formdata_has(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) return JS_NewBool(ctx, 0);

        std::string name = JSValueConverter::toString(ctx, argv[0]);
        JSValue data = JS_GetPropertyStr(ctx, this_val, "__formdata__");
        if (!JS_IsUndefined(data) && !JS_IsNull(data)) {
            JSValue val = JS_GetPropertyStr(ctx, data, name.c_str());
            bool has = !JS_IsUndefined(val) && !JS_IsNull(val);
            JS_FreeValue(ctx, val);
            JS_FreeValue(ctx, data);
            return JS_NewBool(ctx, has ? 1 : 0);
        }
        JS_FreeValue(ctx, data);
        return JS_NewBool(ctx, 0);
    }

    // FormData.prototype.set(name, value)
    JSValue js_formdata_set(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 2) return JS_UNDEFINED;

        std::string name = JSValueConverter::toString(ctx, argv[0]);
        std::string value = JSValueConverter::toString(ctx, argv[1]);

        JSValue data = JS_GetPropertyStr(ctx, this_val, "__formdata__");
        if (!JS_IsUndefined(data) && !JS_IsNull(data)) {
            JS_SetPropertyStr(ctx, data, name.c_str(), JS_NewString(ctx, value.c_str()));
        }
        JS_FreeValue(ctx, data);

        return JS_UNDEFINED;
    }

    // FormData.prototype.delete(name)
    JSValue js_formdata_delete(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) return JS_UNDEFINED;

        std::string name = JSValueConverter::toString(ctx, argv[0]);
        JSValue data = JS_GetPropertyStr(ctx, this_val, "__formdata__");
        if (!JS_IsUndefined(data) && !JS_IsNull(data)) {
            JSAtom atom = JS_NewAtom(ctx, name.c_str());
            JS_DeleteProperty(ctx, data, atom, 0);
            JS_FreeAtom(ctx, atom);
        }
        JS_FreeValue(ctx, data);

        return JS_UNDEFINED;
    }

    // FormData 객체 등록
    void registerFormDataObject(JSContext* ctx, JSValue global_obj) {
        // FormData 생성자 등록
        JSValue formdata_ctor = JS_NewCFunction2(ctx, js_formdata_constructor, "FormData", 1, JS_CFUNC_constructor, 0);
        
        // FormData.prototype 생성
        JSValue formdata_proto = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, formdata_proto, "append", JS_NewCFunction(ctx, js_formdata_append, "append", 2));
        JS_SetPropertyStr(ctx, formdata_proto, "get", JS_NewCFunction(ctx, js_formdata_get, "get", 1));
        JS_SetPropertyStr(ctx, formdata_proto, "has", JS_NewCFunction(ctx, js_formdata_has, "has", 1));
        JS_SetPropertyStr(ctx, formdata_proto, "set", JS_NewCFunction(ctx, js_formdata_set, "set", 2));
        JS_SetPropertyStr(ctx, formdata_proto, "delete", JS_NewCFunction(ctx, js_formdata_delete, "delete", 1));
        
        // toString() 메서드 추가 - fetch의 body로 사용될 때 호출됨
        JS_SetPropertyStr(ctx, formdata_proto, "toString", JS_NewCFunction(ctx, 
            [](JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) -> JSValue {
                JSValue data = JS_GetPropertyStr(ctx, this_val, "__formdata__");
                if (JS_IsUndefined(data) || JS_IsNull(data)) {
                    JS_FreeValue(ctx, data);
                    return JS_NewString(ctx, "");
                }

                // URL-encoded 형식으로 변환
                std::string result;
                JSPropertyEnum* props;
                uint32_t prop_count;
                
                if (JS_GetOwnPropertyNames(ctx, &props, &prop_count, data, JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0) {
                    for (uint32_t i = 0; i < prop_count; i++) {
                        const char* key = JS_AtomToCString(ctx, props[i].atom);
                        JSValue val = JS_GetProperty(ctx, data, props[i].atom);
                        
                        if (key) {
                            std::string value = JSValueConverter::toString(ctx, val);
                            if (!result.empty()) result += "&";
                            result += std::string(key) + "=" + value;
                            JS_FreeCString(ctx, key);
                        }
                        JS_FreeValue(ctx, val);
                    }
                    js_free(ctx, props);
                }

                JS_FreeValue(ctx, data);
                return JS_NewString(ctx, result.c_str());
            }, "toString", 0));

        JS_SetPropertyStr(ctx, formdata_ctor, "prototype", formdata_proto);
        JS_SetPropertyStr(ctx, global_obj, "FormData", formdata_ctor);
    }
}
