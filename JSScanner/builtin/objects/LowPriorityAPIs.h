#pragma once
#include "../../quickjs.h"

/**
 * Low Priority APIs (Priority: LOW)
 * 
 * - Notification: 피싱 알림
 * - Geolocation: 위치 추적
 * - Clipboard: 클립보드 접근
 * - WebRTC: IP 유출
 * - requestAnimationFrame: 타이밍 공격
 */
namespace LowPriorityAPIs {
    
    void registerLowPriorityAPIs(JSContext* ctx, JSValue global_obj);

    // Notification
    JSValue js_notification_constructor(JSContext* ctx, JSValueConst new_target, 
                                       int argc, JSValueConst* argv);
    JSValue js_notification_requestPermission(JSContext* ctx, JSValueConst this_val, 
                                             int argc, JSValueConst* argv);

    // Geolocation
    JSValue js_geolocation_getCurrentPosition(JSContext* ctx, JSValueConst this_val, 
                                             int argc, JSValueConst* argv);
    JSValue js_geolocation_watchPosition(JSContext* ctx, JSValueConst this_val, 
                                        int argc, JSValueConst* argv);

    // Clipboard
    JSValue js_clipboard_writeText(JSContext* ctx, JSValueConst this_val, 
                                   int argc, JSValueConst* argv);
    JSValue js_clipboard_readText(JSContext* ctx, JSValueConst this_val, 
                                  int argc, JSValueConst* argv);

    // WebRTC
    JSValue js_rtc_peerconnection_constructor(JSContext* ctx, JSValueConst new_target, 
                                              int argc, JSValueConst* argv);

    // requestAnimationFrame
    JSValue js_requestAnimationFrame(JSContext* ctx, JSValueConst this_val, 
                                     int argc, JSValueConst* argv);

} // namespace LowPriorityAPIs
