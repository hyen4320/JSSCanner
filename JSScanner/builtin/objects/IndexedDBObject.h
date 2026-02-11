#pragma once
#include "../../quickjs.h"

/**
 * IndexedDB - 대용량 악성 데이터 저장소 탐지 (Priority: HIGH)
 * 
 * 🎯 탐지 목적:
 * - 대용량 악성 페이로드 저장 탐지
 * - 지속성 악성코드 데이터베이스 감시
 * - 민감 정보 저장 모니터링
 * 
 * 🚨 악성 행위 패턴:
 * 1. 대용량 데이터 저장 (>1MB) → Severity 8
 * 2. 민감 정보 저장 → Severity 10
 * 3. 암호화된 Blob 저장 → Severity 9
 */
namespace IndexedDBObject {
    
    void registerIndexedDBObject(JSContext* ctx, JSValue global_obj);

    // indexedDB.open()
    JSValue js_indexeddb_open(JSContext* ctx, JSValueConst this_val, 
                             int argc, JSValueConst* argv);

    // IDBDatabase methods (stub implementations)
    JSValue js_idbdatabase_transaction(JSContext* ctx, JSValueConst this_val, 
                                      int argc, JSValueConst* argv);
    JSValue js_idbobjectstore_add(JSContext* ctx, JSValueConst this_val, 
                                  int argc, JSValueConst* argv);
    JSValue js_idbobjectstore_put(JSContext* ctx, JSValueConst this_val, 
                                  int argc, JSValueConst* argv);

} // namespace IndexedDBObject
