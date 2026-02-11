#pragma once
#include "../../quickjs.h"

/**
 * Proxy 기반 ReferenceError 예외처리
 * 정의되지 않은 글로벌 객체/API에 대한 폴백 처리
 */
namespace ProxyFallbackObject {
    /**
     * 글로벌 객체에 Proxy 기반 폴백 설치
     * @param ctx JavaScript 컨텍스트
     * @param global_obj Global 객체
     */
    void installProxyFallback(JSContext* ctx, JSValue global_obj);
}
