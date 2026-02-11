#include "pch.h"
#include "ProxyFallbackObject.h"
#include "../../core/JSAnalyzer.h"
#include "../helpers/JSValueConverter.h"
#include <cstdio>

namespace ProxyFallbackObject {
    
    // 분석 컨텍스트 가져오기
    static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
        return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
    }

    void installProxyFallback(JSContext* ctx, JSValue global_obj) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        
        // ===== 로그: 시작 (printf로 직접 출력) =====
        printf("[ProxyFallback] ===== INSTALLATION START =====\n");
        
        if (a_ctx && a_ctx->findings) {
            a_ctx->findings->push_back({0, "[ProxyFallback] ===== INSTALLATION START =====", "system_info"});
        }
        
        // ===== 1. window 객체 확인 =====
        printf("[ProxyFallback] Step 1: Checking window object...\n");
        
        JSValue window_obj = JS_GetPropertyStr(ctx, global_obj, "window");
        
        if (JS_IsObject(window_obj)) {
            printf("[ProxyFallback] Step 1: window object found\n");
            
            // addEventListener가 이미 있는지 확인
            JSValue addEventListener_val = JS_GetPropertyStr(ctx, window_obj, "addEventListener");
            if (JS_IsFunction(ctx, addEventListener_val)) {
                printf("[ProxyFallback] Step 1: window.addEventListener already exists (GOOD)\n");
            } else {
                printf("[ProxyFallback] Step 1: window.addEventListener NOT FOUND (BAD)\n");
            }
            JS_FreeValue(ctx, addEventListener_val);
        } else {
            printf("[ProxyFallback] Step 1: ERROR - window object NOT FOUND\n");
        }
        JS_FreeValue(ctx, window_obj);
        
        // ===== 2. document 객체 확인 =====
        printf("[ProxyFallback] Step 2: Checking document object...\n");
        
        JSValue document_obj = JS_GetPropertyStr(ctx, global_obj, "document");
        
        if (JS_IsObject(document_obj)) {
            printf("[ProxyFallback] Step 2: document object found\n");
            
            // addEventListener가 이미 있는지 확인
            JSValue addEventListener_val = JS_GetPropertyStr(ctx, document_obj, "addEventListener");
            if (JS_IsFunction(ctx, addEventListener_val)) {
                printf("[ProxyFallback] Step 2: document.addEventListener already exists (GOOD)\n");
            } else {
                printf("[ProxyFallback] Step 2: document.addEventListener NOT FOUND (BAD)\n");
            }
            JS_FreeValue(ctx, addEventListener_val);
            
            // document.body 확인
            JSValue body_obj = JS_GetPropertyStr(ctx, document_obj, "body");
            if (JS_IsObject(body_obj)) {
                printf("[ProxyFallback] Step 2: document.body found\n");
                
                JSValue body_addEventListener = JS_GetPropertyStr(ctx, body_obj, "addEventListener");
                if (JS_IsFunction(ctx, body_addEventListener)) {
                    printf("[ProxyFallback] Step 2: document.body.addEventListener already exists (GOOD)\n");
                } else {
                    printf("[ProxyFallback] Step 2: document.body.addEventListener NOT FOUND (BAD)\n");
                }
                JS_FreeValue(ctx, body_addEventListener);
            } else {
                printf("[ProxyFallback] Step 2: document.body NOT FOUND\n");
            }
            JS_FreeValue(ctx, body_obj);
        } else {
            printf("[ProxyFallback] Step 2: ERROR - document object NOT FOUND\n");
        }
        JS_FreeValue(ctx, document_obj);
        
        // ===== 3. 전역 addEventListener 확인 =====
        printf("[ProxyFallback] Step 3: Checking global addEventListener...\n");
        
        JSValue global_addEventListener = JS_GetPropertyStr(ctx, global_obj, "addEventListener");
        if (JS_IsFunction(ctx, global_addEventListener)) {
            printf("[ProxyFallback] Step 3: global addEventListener exists (GOOD)\n");
        } else {
            printf("[ProxyFallback] Step 3: global addEventListener NOT FOUND (BAD)\n");
        }
        JS_FreeValue(ctx, global_addEventListener);
        
        // ===== 로그: 완료 =====
        printf("[ProxyFallback] ===== INSTALLATION COMPLETED =====\n");
        
        if (a_ctx && a_ctx->findings) {
            a_ctx->findings->push_back({0, "[ProxyFallback] ===== INSTALLATION COMPLETED =====", "system_info"});
        }
    }
}
