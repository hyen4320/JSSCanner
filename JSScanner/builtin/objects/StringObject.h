#pragma once
#include "../../quickjs.h"

/**
 * String 객체의 함수들
 */
namespace StringObject {
    /**
     * String 객체 함수들을 등록
     * @param ctx JavaScript 컨텍스트
     * @param global_obj Global 객체
     */
    void registerStringFunctions(JSContext* ctx, JSValue global_obj);

    // String.fromCharCode
    JSValue js_string_fromCharCode(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
}
