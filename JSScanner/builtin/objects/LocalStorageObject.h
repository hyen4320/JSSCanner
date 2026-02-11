#pragma once
#include "../../quickjs.h"
#include <unordered_map>
#include <string>

/**
 * LocalStorage 객체의 함수들
 */
namespace LocalStorageObject {
    /**
     * LocalStorage 객체를 생성하고 등록
     * @param ctx JavaScript 컨텍스트
     * @param global_obj Global 객체
     */
    void registerLocalStorageObject(JSContext* ctx, JSValue global_obj);

    // LocalStorage 메서드들
    JSValue js_localStorage_getItem(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_localStorage_setItem(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_localStorage_removeItem(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_localStorage_clear(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);

    // LocalStorage 스토리지 (멀티스레드 안전성을 위해 thread_local 사용)
    extern thread_local std::unordered_map<std::string, std::string> g_local_storage;
}
