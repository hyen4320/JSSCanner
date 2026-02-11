#pragma once

#include <string>
#include <map>
#include <set>
#include "../../../../mon47-opensrc/opensrc/quickjs-ng/include/quickjs.h"
#include "../../hooks/Hook.h"

struct JSAnalyzerContext;

// 🔥 extern 제거 - 전역 Class ID 더 이상 사용하지 않음 (멀티스레드 안전성)

class ActiveXObject {
public:
    ActiveXObject(JSContext* ctx, JSAnalyzerContext* a_ctx, const std::string& progID);
    ~ActiveXObject();

    // Static factory method for JavaScript constructor
    static JSValue js_constructor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv);

    // Common ActiveX methods (각 메서드별 핸들러)
    static JSValue js_run(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    static JSValue js_exec(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    static JSValue js_createTextFile(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    static JSValue js_openTextFile(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    static JSValue js_deleteFile(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    static JSValue js_send(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    static JSValue js_open(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    
    static JSValue js_method_call(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    static JSValue js_property_get(JSContext* ctx, JSValueConst this_val, JSAtom prop);
    static JSValue js_property_set(JSContext* ctx, JSValueConst this_val, JSAtom prop, JSValueConst val);

    // Helper to get ActiveXObject from JSValue
    static ActiveXObject* getThis(JSValueConst this_val);  // 🔥 deprecated
    static ActiveXObject* getThis(JSContext* ctx, JSValueConst this_val);  // 🔥 새로운 메서드

    // 🔥 QuickJS 등록 관련 함수 (JSAnalyzer에서 호출)
    static void registerClass(JSContext* ctx, JSRuntime* rt, JSValue global_obj, JSClassID class_id);

    const std::string& getProgID() const { return progID; }

    // 🔥 finalizer에서 shutdown 시 ctx 무효화를 위해 public으로 변경
    JSContext* ctx;

private:
    JSRuntime* rt;
    JSAnalyzerContext* a_ctx;

    std::string progID;
    std::map<std::string, JSValue> properties;

    void analyzeActiveXSecurity(const std::string& progID);
    void analyzeMethodCall(const std::string& methodName, const std::vector<std::string>& args);
    bool isSensitiveProgID(const std::string& progID) const;
    std::string generateMockResponse(const std::string& methodName);

    static const std::set<std::string> DANGEROUS_PROGIDS;
    static const std::set<std::string> FILE_SYSTEM_PROGIDS;
    static const std::set<std::string> SHELL_PROGIDS;
    static const std::set<std::string> NETWORK_PROGIDS;
};
