#pragma once
#include "../../quickjs.h"

/**
 * ShadowDOM/MutationObserver/SessionStorage (Priority: MEDIUM)
 * 
 * 🎯 탐지 목적:
 * - ShadowDOM: DOM 은폐 기법 탐지
 * - MutationObserver: 동적 DOM 조작 감시
 * - SessionStorage: 세션 데이터 추적
 */
namespace MediumPriorityAPIs {
    
    void registerMediumPriorityAPIs(JSContext* ctx, JSValue global_obj);

    // ShadowDOM
    JSValue js_element_attachShadow(JSContext* ctx, JSValueConst this_val, 
                                   int argc, JSValueConst* argv);

    // MutationObserver
    JSValue js_mutation_observer_constructor(JSContext* ctx, JSValueConst new_target, 
                                            int argc, JSValueConst* argv);
    JSValue js_mutation_observer_observe(JSContext* ctx, JSValueConst this_val, 
                                        int argc, JSValueConst* argv);

    // SessionStorage
    JSValue js_sessionstorage_setItem(JSContext* ctx, JSValueConst this_val, 
                                     int argc, JSValueConst* argv);
    JSValue js_sessionstorage_getItem(JSContext* ctx, JSValueConst this_val, 
                                     int argc, JSValueConst* argv);

} // namespace MediumPriorityAPIs
