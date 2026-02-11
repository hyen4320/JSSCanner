#include "pch.h"
#include "JSValueConverter.h"

namespace JSValueConverter {
    std::string toString(JSContext* ctx, JSValueConst value) {
        size_t len = 0;
        const char* cstr = JS_ToCStringLen2(ctx, &len, value, 0);
        if (!cstr) {
            return "";
        }
        std::string result(cstr, len);
        JS_FreeCString(ctx, cstr);
        return result;
    }

    std::string toJsonString(JSContext* ctx, JSValueConst value) {
        JSValue json = JS_JSONStringify(ctx, value, JS_UNDEFINED, JS_UNDEFINED);
        if (JS_IsException(json)) {
            JSValue exception = JS_GetException(ctx);
            JS_FreeValue(ctx, exception);
            return "";
        }
        std::string result = toString(ctx, json);
        JS_FreeValue(ctx, json);
        return result;
    }
}
