#pragma once
#include "../../quickjs.h"

/**
 * Math 객체의 후킹 함수들
 */
namespace MathObject {
    /**
     * Math 객체 함수들을 등록
     * @param ctx JavaScript 컨텍스트
     * @param global_obj Global 객체
     */
    void registerMathFunctions(JSContext* ctx, JSValue global_obj);

    // Math 함수들 (magic 값 사용)
    JSValue js_math_generic_hook(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic);
}
