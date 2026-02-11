#pragma once
#include "../../quickjs.h"

/**
 * Crypto.subtle API - 암호화 페이로드 탐지 (Priority: HIGH)
 * 
 * 🎯 탐지 목적:
 * - 암호화된 악성 페이로드 탐지
 * - 크립토마이닝 감지
 * - 암호화 통신 모니터링
 * 
 * 🚨 악성 행위 패턴:
 * 1. encrypt + network → Severity 9
 * 2. 빈번한 암호화 작업 → Severity 8 (마이닝)
 * 3. importKey → Severity 7
 */
namespace CryptoSubtleObject {
    
    void registerCryptoSubtleObject(JSContext* ctx, JSValue global_obj);

    JSValue js_crypto_subtle_encrypt(JSContext* ctx, JSValueConst this_val, 
                                     int argc, JSValueConst* argv);
    JSValue js_crypto_subtle_decrypt(JSContext* ctx, JSValueConst this_val, 
                                     int argc, JSValueConst* argv);
    JSValue js_crypto_subtle_importKey(JSContext* ctx, JSValueConst this_val, 
                                       int argc, JSValueConst* argv);
    JSValue js_crypto_subtle_generateKey(JSContext* ctx, JSValueConst this_val, 
                                         int argc, JSValueConst* argv);

} // namespace CryptoSubtleObject
