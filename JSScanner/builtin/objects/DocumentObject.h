#pragma once
#include "../../quickjs.h"
#include <string>

/**
 * Document 객체의 메서드들
 */
namespace DocumentObject {
    /**
     * Document 객체를 생성하고 등록
     * @param ctx JavaScript 컨텍스트
     * @param global_obj Global 객체
     */
    void registerDocumentObject(JSContext* ctx, JSValue global_obj);

    // Document 메서드들
    JSValue js_document_write_hook(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_document_getElementById(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_document_createElement(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_document_addEventListener(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_document_querySelector(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_document_querySelectorAll(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_document_get_cookie(JSContext* ctx, JSValueConst this_val);
    JSValue js_document_set_cookie(JSContext* ctx, JSValueConst this_val, JSValueConst val);
    
    // documentElement.innerHTML setter (추가)
    JSValue js_document_element_set_innerHTML(JSContext* ctx, JSValueConst this_val, JSValueConst val);

    // Cookie 스토리지 (멀티스레드 안전성을 위해 thread_local 사용)
    extern thread_local std::string g_cookie_storage;
}
