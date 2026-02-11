#pragma once
#include "../../quickjs.h"

/**
 * WebSocket 객체 - 원격 제어 탐지 (Priority: HIGH)
 * 
 * 🎯 탐지 목적:
 * - C&C 서버와의 WebSocket 연결 탐지
 * - 실시간 원격 명령 수신/실행 감지
 * - 양방향 통신 채널 모니터링
 * 
 * 🚨 악성 행위 패턴:
 * 1. ws:// (비암호화) 연결 → Severity 10
 * 2. wss:// 연결 + eval/Function → Severity 9
 * 3. 민감 데이터 전송 (cookie, token) → Severity 10
 * 4. onmessage에서 eval() 실행 → Severity 10
 */
namespace WebSocketObject {
    
    /**
     * WebSocket 객체를 전역 스코프에 등록
     * @param ctx JavaScript 컨텍스트
     * @param global_obj Global 객체 (window)
     */
    void registerWebSocketObject(JSContext* ctx, JSValue global_obj);

    // Constructor
    JSValue js_websocket_constructor(JSContext* ctx, JSValueConst new_target, 
                                     int argc, JSValueConst* argv);

    // Methods
    JSValue js_websocket_send(JSContext* ctx, JSValueConst this_val, 
                             int argc, JSValueConst* argv);
    JSValue js_websocket_close(JSContext* ctx, JSValueConst this_val, 
                              int argc, JSValueConst* argv);

    // Event Handlers (setters)
    JSValue js_websocket_set_onmessage(JSContext* ctx, JSValueConst this_val, 
                                       JSValueConst val);
    JSValue js_websocket_set_onerror(JSContext* ctx, JSValueConst this_val, 
                                     JSValueConst val);
    JSValue js_websocket_set_onopen(JSContext* ctx, JSValueConst this_val, 
                                    JSValueConst val);
    JSValue js_websocket_set_onclose(JSContext* ctx, JSValueConst this_val, 
                                     JSValueConst val);

    // Getters
    JSValue js_websocket_get_readyState(JSContext* ctx, JSValueConst this_val);
    JSValue js_websocket_get_url(JSContext* ctx, JSValueConst this_val);

} // namespace WebSocketObject
