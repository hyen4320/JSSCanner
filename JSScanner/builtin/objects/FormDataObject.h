#pragma once
#include "../../quickjs.h"

/**
 * FormData 객체의 메서드들
 */
namespace FormDataObject {
    /**
     * FormData 생성자
     */
    JSValue js_formdata_constructor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv);

    /**
     * FormData.prototype.append()
     */
    JSValue js_formdata_append(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);

    /**
     * FormData.prototype.get()
     */
    JSValue js_formdata_get(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);

    /**
     * FormData.prototype.has()
     */
    JSValue js_formdata_has(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);

    /**
     * FormData.prototype.set()
     */
    JSValue js_formdata_set(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);

    /**
     * FormData.prototype.delete()
     */
    JSValue js_formdata_delete(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);

    /**
     * FormData 객체 등록
     */
    void registerFormDataObject(JSContext* ctx, JSValue global_obj);
}
