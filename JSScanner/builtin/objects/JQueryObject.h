#pragma once
#include "../../quickjs.h"

/**
 * jQuery 객체 모킹
 */
namespace JQueryObject {
    /**
     * jQuery 객체를 생성하고 등록
     * @param ctx JavaScript 컨텍스트
     * @param global_obj Global 객체
     */
    void registerJQueryObject(JSContext* ctx, JSValue global_obj);
}
