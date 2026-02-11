#pragma once
#include "../../quickjs.h"

/**
 * WebAssembly - WASM 악성코드 & 크립토마이닝 탐지 (Priority: MEDIUM)
 * 
 * 🎯 탐지 목적:
 * - WASM을 통한 악성 코드 실행 탐지
 * - 크립토마이닝 패턴 감지
 * - 네이티브 수준의 위협 감지
 * - 의심스러운 imports 분석
 * 
 * 🚨 악성 행위 패턴:
 * 1. 크립토마이닝 (함수 100+, 메모리, 50KB+) → Severity 10
 * 2. 의심스러운 imports (fetch, crypto, eval) → Severity 9
 * 3. 대용량 모듈 (>100KB) → Severity 8
 * 4. 일반 WASM 인스턴스화 → Severity 7
 * 
 * 📊 분석 기능:
 * - WASM 바이트코드 파싱
 * - 모듈 크기 측정
 * - Function/Import 개수 계산
 * - Memory/Table 섹션 감지
 */
namespace WebAssemblyObject {
    
    void registerWebAssemblyObject(JSContext* ctx, JSValue global_obj);

    JSValue js_wasm_instantiate(JSContext* ctx, JSValueConst this_val, 
                                int argc, JSValueConst* argv);
    JSValue js_wasm_compile(JSContext* ctx, JSValueConst this_val, 
                           int argc, JSValueConst* argv);

} // namespace WebAssemblyObject
