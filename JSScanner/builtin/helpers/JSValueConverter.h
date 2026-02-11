#pragma once
#include "../../quickjs.h"
#include <string>

namespace JSValueConverter {
    /**
     * JSValue를 std::string으로 변환
     * @param ctx JavaScript 컨텍스트
     * @param value 변환할 JSValue
     * @return 변환된 문자열
     */
    std::string toString(JSContext* ctx, JSValueConst value);

    /**
     * JSValue를 JSON 문자열로 변환
     * @param ctx JavaScript 컨텍스트
     * @param value 변환할 JSValue
     * @return JSON 문자열
     */
    std::string toJsonString(JSContext* ctx, JSValueConst value);
}
