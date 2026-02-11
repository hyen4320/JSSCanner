#pragma once
#include "../../quickjs.h"

/**
 * Navigator 객체 - 정보 유출 및 환경 탐지 (Priority: MEDIUM)
 * 
 * 🎯 탐지 목적:
 * - sendBeacon을 통한 데이터 유출 탐지
 * - 환경 정보 수집 감시
 * 
 * 🚨 악성 행위 패턴:
 * 1. sendBeacon + 민감 데이터 → Severity 10
 * 2. sendBeacon 빈번한 호출 → Severity 8
 */
namespace NavigatorObject {
    
    void registerNavigatorObject(JSContext* ctx, JSValue global_obj);

    JSValue js_navigator_sendBeacon(JSContext* ctx, JSValueConst this_val, 
                                    int argc, JSValueConst* argv);

} // namespace NavigatorObject
