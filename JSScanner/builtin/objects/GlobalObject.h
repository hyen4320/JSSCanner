#pragma once
#include "../../quickjs.h"

/**
 * Global 객체의 함수들 (print, eval, atob, setTimeout, setInterval, clearTimeout, clearInterval)
 */
namespace GlobalObject {
    /**
     * JSAnalyzer에서 Global 객체 함수들을 등록
     * @param ctx JavaScript 컨텍스트
     * @param global_obj Global 객체
     */
    void registerGlobalFunctions(JSContext* ctx, JSValue global_obj);

    // 개별 함수들
    JSValue js_print(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_eval_hook(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_atob(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_setTimeout(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_setInterval(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_clearTimeout(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_clearInterval(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
}
