#pragma once
#include "../../quickjs.h"

/**
 * Element 객체의 메서드들
 */
namespace ElementObject {
    /**
     * Element 메서드들 (헤더에서 선언만, MockHelpers에서 사용)
     */
    JSValue js_element_addEventListener(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_element_setAttribute(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_element_getAttribute(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_element_hasAttribute(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_element_removeAttribute(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_element_appendChild(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    
    // ClassList 메서드들
    JSValue js_classList_add(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_classList_remove(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_classList_contains(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
}
