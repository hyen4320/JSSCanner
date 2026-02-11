#pragma once
#include "../../quickjs.h"

/**
 * Worker/SharedWorker 객체 - 백그라운드 악성코드 탐지 (Priority: HIGH)
 * 
 * 🎯 탐지 목적:
 * - 백그라운드에서 실행되는 악성 스크립트 탐지
 * - 메인 스레드 우회 악성 코드 감지
 * - Worker를 통한 데이터 유출 모니터링
 * - SharedWorker를 통한 탭 간 통신 감지
 * 
 * 🚨 악성 행위 패턴:
 * 1. Worker 내부에서 fetch/XHR → Severity 9
 * 2. postMessage로 민감 데이터 전송 → Severity 10
 * 3. 암호화 작업 (크립토마이닝) → Severity 8
 * 4. Blob URL로 Worker 생성 (난독화) → Severity 9
 * 5. SharedWorker로 탭 간 데이터 공유 → Severity 9
 */
namespace WorkerObject {
    
    void registerWorkerObject(JSContext* ctx, JSValue global_obj);

    // Worker Constructor
    JSValue js_worker_constructor(JSContext* ctx, JSValueConst new_target, 
                                  int argc, JSValueConst* argv);

    // SharedWorker Constructor
    JSValue js_sharedworker_constructor(JSContext* ctx, JSValueConst new_target, 
                                        int argc, JSValueConst* argv);

    // Methods
    JSValue js_worker_postMessage(JSContext* ctx, JSValueConst this_val, 
                                  int argc, JSValueConst* argv);
    JSValue js_worker_terminate(JSContext* ctx, JSValueConst this_val, 
                                int argc, JSValueConst* argv);

    // Event Handlers
    JSValue js_worker_set_onmessage(JSContext* ctx, JSValueConst this_val, 
                                    JSValueConst val);
    JSValue js_worker_set_onerror(JSContext* ctx, JSValueConst this_val, 
                                  JSValueConst val);

} // namespace WorkerObject
