#pragma once
#include "../../quickjs.h"

/**
 * Blob/File API - 악성 파일 생성 탐지 (Priority: HIGH)
 * 
 * 🎯 탐지 목적:
 * - 동적으로 생성된 악성 파일 탐지
 * - Blob URL을 통한 페이로드 은폐 감지
 * - 파일 다운로드 트릭 모니터링
 * 
 * 🚨 악성 행위 패턴:
 * 1. JS/HTML 파일 생성 → Severity 9
 * 2. 암호화된 Blob → Severity 8
 * 3. URL.createObjectURL 사용 → Severity 8
 */
namespace BlobObject {
    
    void registerBlobObject(JSContext* ctx, JSValue global_obj);

    // Blob constructor
    JSValue js_blob_constructor(JSContext* ctx, JSValueConst new_target, 
                               int argc, JSValueConst* argv);

    // URL.createObjectURL
    JSValue js_url_createObjectURL(JSContext* ctx, JSValueConst this_val, 
                                   int argc, JSValueConst* argv);
    JSValue js_url_revokeObjectURL(JSContext* ctx, JSValueConst this_val, 
                                   int argc, JSValueConst* argv);

} // namespace BlobObject
