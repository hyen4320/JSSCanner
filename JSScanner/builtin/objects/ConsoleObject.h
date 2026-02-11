#pragma once
#include "../../quickjs.h"

/**
 * Console 객체 - 디버깅 정보 유출 탐지 (Priority: LOW)
 * 
 * 🎯 탐지 목적:
 * - 민감한 정보 콘솔 로깅 감지
 * - 과도한 로깅 (anti-debugging) 탐지
 * - eval/Function 코드 로깅 감지
 * - Base64 인코딩된 데이터 로깅
 * 
 * 🚨 악성 행위 패턴:
 * 1. 민감 데이터 로깅 → Severity 8-9
 * 2. eval/Function 코드 → Severity 7
 * 3. 과도한 로깅 (>20/5초) → Severity 7
 * 4. Base64 인코딩 → Severity 6
 * 5. Stack trace 노출 → Severity 6
 */
namespace ConsoleObject {
    /**
     * Console 객체를 생성하고 등록
     * @param ctx JavaScript 컨텍스트
     * @param global_obj Global 객체
     */
    void registerConsoleObject(JSContext* ctx, JSValue global_obj);

    // Console 메서드들
    JSValue js_console_log(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_console_warn(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_console_error(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
}
