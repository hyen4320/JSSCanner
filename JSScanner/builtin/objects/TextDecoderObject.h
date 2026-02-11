#pragma once
#include "../../quickjs.h"

/**
 * TextDecoder 객체의 후킹 함수들
 * Web Encoding API - 바이트 배열을 텍스트로 디코딩
 */
namespace TextDecoderObject {
    /**
     * TextDecoder 객체를 등록
     * @param ctx JavaScript 컨텍스트
     * @param global_obj Global 객체
     */
    void registerTextDecoder(JSContext* ctx, JSValue global_obj);

    // TextDecoder 생성자
    JSValue js_textdecoder_constructor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv);
    
    // TextDecoder.prototype.decode
    JSValue js_textdecoder_decode(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    
    // TextDecoder.prototype.encoding getter
    JSValue js_textdecoder_encoding_get(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
}
