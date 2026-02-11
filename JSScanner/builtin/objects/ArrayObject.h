#pragma once
#include "../../quickjs.h"

/**
 * Array 객체의 프로토타입 함수들
 */
namespace ArrayObject {
    /**
     * Array 프로토타입 함수들을 등록
     * @param ctx JavaScript 컨텍스트
     * @param global_obj Global 객체
     */
    void registerArrayFunctions(JSContext* ctx, JSValue global_obj);

    // Array 프로토타입 메서드들
    JSValue js_array_join(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_array_push(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_array_pop(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_array_slice(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    
    // Uint8Array 정적 메서드들
    JSValue js_uint8array_from(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
}
