#pragma once
#include "../../quickjs.h"

/**
 * Window 객체의 메서드들
 */
namespace WindowObject {
    /**
     * Window 객체를 생성하고 등록
     * @param ctx JavaScript 컨텍스트
     * @param global_obj Global 객체
     */
    void registerWindowObject(JSContext* ctx, JSValue global_obj);

    // Window.location 메서드들
    JSValue js_window_location_set_href(JSContext* ctx, JSValueConst this_val, JSValueConst val);
    JSValue js_window_location_replace(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_window_location_assign(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);

    // Fetch API
    JSValue js_fetch(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    
    // Environment Detection (추가)
    JSValue js_navigator_get_userAgent(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_window_get_innerWidth(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_window_get_innerHeight(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_window_stop(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    
    // Clipboard API
    JSValue js_navigator_clipboard_writeText(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_navigator_clipboard_write(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    
    // 🔥 NEW: window.open
    JSValue js_window_open(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
}
