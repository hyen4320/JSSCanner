#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include "../../../../mon47-opensrc/opensrc/quickjs-ng/include/quickjs.h"
#include "../../hooks/Hook.h"

struct JSAnalyzerContext;

// 🔥 extern 제거 - 전역 Class ID 더 이상 사용하지 않음

// struct JSAnalyzerContext; // Removed redundant forward declaration

class XMLHTTPRequestObject {
public:
    static const int UNSENT = 0;
    static const int OPENED = 1;
    static const int HEADERS_RECEIVED = 2;
    static const int LOADING = 3;
    static const int DONE = 4;

    XMLHTTPRequestObject(JSContext* ctx, JSAnalyzerContext* a_ctx);
    ~XMLHTTPRequestObject();

    static JSValue js_open(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    static JSValue js_send(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    static JSValue js_setRequestHeader(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);

    void open(const std::string& method, const std::string& url, bool async);
    void send(const std::string& body);
    void setRequestHeader(const std::string& header, const std::string& value);

    int getReadyState() const { return readyState; }
    int getStatus() const { return status; }
    const std::string& getResponseText() const { return responseText; }
    void setOnReadyStateChange(JSValue callback);

    static XMLHTTPRequestObject* getThis(JSValueConst this_val);  // 🔥 deprecated
    static XMLHTTPRequestObject* getThis(JSContext* ctx, JSValueConst this_val);  // 🔥 새로운 메서드

    // 🔥 QuickJS 등록 관련 함수 (JSAnalyzer에서 호출)
    static void registerClass(JSContext* ctx, JSRuntime* rt, JSValue global_obj, JSClassID class_id);

    JSValue onreadystatechangeCallback;

    // 🔥 finalizer에서 shutdown 시 ctx 무효화를 위해 public으로 변경
    JSContext* ctx;

private:
    JSRuntime* rt;
    JSAnalyzerContext* a_ctx; // Added member

    std::string method;
    std::string url;
    bool async;
    std::string responseText;
    int status;
    int readyState;
    std::map<std::string, std::string> requestHeaders;

    void analyzeXHRSecurity(const std::string& method, const std::string& url);
    void analyzeRequestSecurity(const std::string& method, const std::string& url, const std::string& body, const std::map<std::string, std::string>& headers);

    void simulateResponse();
    std::string generateMockResponse();
    void triggerReadyStateChange();

    static const std::set<std::string> SENSITIVE_KEYWORDS;
};
