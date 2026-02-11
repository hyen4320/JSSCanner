#include "pch.h"
#include "XMLHTTPRequestObject.h"
#include "../../hooks/Hook.h"
#include "../../core/DynamicStringTracker.h"
#include "../../core/ChainTrackerManager.h"
#include "../../core/JSAnalyzer.h" // For JSAnalyzerContext

// Forward declaration of JSAnalyzerContext is no longer needed here as JSAnalyzer.h is included
// struct JSAnalyzerContext; // Remove this line if it exists

const std::set<std::string> XMLHTTPRequestObject::SENSITIVE_KEYWORDS = {
    "password", "passwd", "pwd",
    "token", "auth", "authorization", "bearer",
    "email", "mail", "e-mail",
    "username", "user", "userid", "user_id", "uname",
    "id", "account", "login", "signin",
    "cookie", "session", "sessionid", "sess",
    "secret", "key", "apikey", "api_key", "access_key",
    "credit", "card", "ssn", "social"
};

// 🔥 런타임에서 Class ID 가져오기 위한 구조체 (JSAnalyzer.cpp에 정의됨)
struct RuntimeClassIDs {
    JSClassID xhr_class_id;
    JSClassID activex_class_id;
};

// 🔥 Context에서 XHR Class ID 가져오기
static JSClassID getXHRClassID(JSContext* ctx) {
    JSRuntime* rt = JS_GetRuntime(ctx);
    RuntimeClassIDs* classIDs = static_cast<RuntimeClassIDs*>(JS_GetRuntimeOpaque(rt));
    return classIDs ? classIDs->xhr_class_id : 0;
}

XMLHTTPRequestObject* XMLHTTPRequestObject::getThis(JSValueConst this_val) {
    // 🔥 deprecated - context 없이는 Class ID를 알 수 없음
    return nullptr;
}

// 🔥 Context를 사용하여 안전하게 가져오기
XMLHTTPRequestObject* XMLHTTPRequestObject::getThis(JSContext* ctx, JSValueConst this_val) {
    JSClassID classID = getXHRClassID(ctx);
    if (classID == 0) return nullptr;
    return static_cast<XMLHTTPRequestObject*>(JS_GetOpaque(this_val, classID));
}

XMLHTTPRequestObject::XMLHTTPRequestObject(JSContext* ctx, JSAnalyzerContext* a_ctx) : ctx(ctx), a_ctx(a_ctx) {
    rt = JS_GetRuntime(ctx);
    this->readyState = 0; // UNSENT
    this->status = 0;
    this->method = "GET";
    this->url = "";
    this->async = true;
    this->responseText = "";
    // 🔥 JS_UNDEFINED로 명시적 초기화
    this->onreadystatechangeCallback = JS_UNDEFINED;
}

XMLHTTPRequestObject::~XMLHTTPRequestObject() {
    // ⚠️ CRITICAL: 소멸자에서 JSValue 해제는 위험함
    // finalizer에서 ctx가 이미 nullptr로 설정되었으면 GC가 자동으로 정리함
    // ctx가 여전히 유효하고 조기 삭제되는 경우에만 해제 시도
    if (ctx && !JS_IsUndefined(onreadystatechangeCallback)) {
        // ⚠️ 하지만 이 시점에서도 ctx가 유효한지 확신할 수 없음
        // Runtime 소멸 중이라면 JS_FreeValue 호출이 크래시를 일으킬 수 있음
        // 따라서 QuickJS GC에 맡기는 것이 가장 안전함
        // JS_FreeValue(ctx, onreadystatechangeCallback);  // ❌ 제거
        onreadystatechangeCallback = JS_UNDEFINED;  // 참조만 제거
    }
}

void XMLHTTPRequestObject::setOnReadyStateChange(JSValue callback) {
    // 🔥 이전 값 해제 후 새 값 설정 (참조 카운트 관리)
    if (!JS_IsUndefined(onreadystatechangeCallback)) {
        JS_FreeValue(ctx, onreadystatechangeCallback);
    }
    onreadystatechangeCallback = JS_DupValue(ctx, callback);
}

void XMLHTTPRequestObject::open(const std::string& method, const std::string& url, bool async) {
    this->method = method;
    this->url = url;
    this->async = async;
    this->readyState = 1; // OPENED
    this->status = 0;
    this->responseText = "";
    this->requestHeaders.clear();
    
    // 🔥 MODIFIED: 메타데이터 포함하여 URL 추가
    if (a_ctx && a_ctx->urlCollector) {
        a_ctx->urlCollector->addUrlWithMetadata(url, "xhr", 0);
    }
    
    if (a_ctx && a_ctx->chainTrackerManager) {
        a_ctx->chainTrackerManager->trackFunctionCall("xhr.open", {JsValue(method), JsValue(url)}, JsValue(std::monostate()));
    }
    analyzeXHRSecurity(method, url);
    triggerReadyStateChange();
}

void XMLHTTPRequestObject::send(const std::string& body) {
    if (a_ctx && a_ctx->chainTrackerManager) {
        a_ctx->chainTrackerManager->trackFunctionCall("xhr.send", {JsValue(body)}, JsValue(std::monostate()));
    }
    analyzeRequestSecurity(method, url, body, requestHeaders);
    simulateResponse();
}

void XMLHTTPRequestObject::setRequestHeader(const std::string& header, const std::string& value) {
    requestHeaders[header] = value;
}

JSValue XMLHTTPRequestObject::js_open(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    XMLHTTPRequestObject* xhr = getThis(ctx, this_val);
    if (!xhr) return JS_EXCEPTION;
    if (argc < 2) return JS_ThrowTypeError(ctx, "Not enough arguments for open()") ;
    const char* method_str = JS_ToCString(ctx, argv[0]);
    const char* url_str = JS_ToCString(ctx, argv[1]);
    std::string method(method_str);
    std::string url(url_str);
    JS_FreeCString(ctx, method_str);
    JS_FreeCString(ctx, url_str);
    bool async = true;
    if (argc >= 3) {
        async = JS_ToBool(ctx, argv[2]);
    }
    xhr->open(method, url, async);
    return JS_UNDEFINED;
}

JSValue XMLHTTPRequestObject::js_send(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    XMLHTTPRequestObject* xhr = getThis(ctx, this_val);
    if (!xhr) return JS_EXCEPTION;
    std::string body = "";
    if (argc > 0 && !JS_IsUndefined(argv[0]) && !JS_IsNull(argv[0])) {
        const char* body_str = JS_ToCString(ctx, argv[0]);
        body = body_str;
        JS_FreeCString(ctx, body_str);
    }
    xhr->send(body);
    return JS_UNDEFINED;
}

JSValue XMLHTTPRequestObject::js_setRequestHeader(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    XMLHTTPRequestObject* xhr = getThis(ctx, this_val);
    if (!xhr) return JS_EXCEPTION;
    if (argc < 2) return JS_ThrowTypeError(ctx, "Not enough arguments for setRequestHeader()") ;
    const char* header_str = JS_ToCString(ctx, argv[0]);
    const char* value_str = JS_ToCString(ctx, argv[1]);
    std::string header(header_str);
    std::string value(value_str);
    JS_FreeCString(ctx, header_str);
    JS_FreeCString(ctx, value_str);
    xhr->setRequestHeader(header, value);
    return JS_UNDEFINED;
}

void XMLHTTPRequestObject::analyzeXHRSecurity(const std::string& method, const std::string& url) {
    if (url.find("ispshellas.gr") != std::string::npos || url.find("naver.php") != std::string::npos || 
        url.find("wp-includes") != std::string::npos || url.find("/dann/") != std::string::npos) {
        if (a_ctx && a_ctx->chainTrackerManager) {
            a_ctx->chainTrackerManager->trackFunctionCall("xhr.suspicious_domain", {JsValue(method), JsValue(url)}, JsValue(std::monostate()));
        }
    }
}

void XMLHTTPRequestObject::analyzeRequestSecurity(const std::string& method, const std::string& url, const std::string& body, const std::map<std::string, std::string>& headers) {
    // 🔥 함수 호출 카운터 증가
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        a_ctx->dynamicAnalyzer->incrementFunctionCallCount();
    }
    
    if (method == "POST" || method == "PUT") {
        if (!body.empty()) {
            std::string lowerBody = body;
            std::transform(lowerBody.begin(), lowerBody.end(), lowerBody.begin(),
                           [](unsigned char c){ return std::tolower(c); });
            bool hasSensitiveData = false;
            std::string detectedKeywords;
            for (const std::string& keyword : SENSITIVE_KEYWORDS) {
                if (lowerBody.find(keyword) != std::string::npos) {
                    hasSensitiveData = true;
                    if (!detectedKeywords.empty()) detectedKeywords += ", ";
                    detectedKeywords += keyword;
                }
            }
            if (hasSensitiveData) {
                std::map<std::string, std::string> metadata;
                metadata["method"] = method;
                metadata["url"] = url;
                metadata["body_snippet"] = body.substr(0, (std::min)((size_t)100, body.length()));
                metadata["detected_keywords"] = detectedKeywords;
                if (a_ctx && a_ctx->chainTrackerManager) {
                    a_ctx->chainTrackerManager->trackFunctionCall("xhr.sensitive_data", {JsValue(method), JsValue(url), JsValue(body)}, JsValue(std::monostate()));
                }
            }
        }
    }
    
    // 🔥 XHR 요청에 대한 recordEvent 추가 (fetch와 동일한 로직)
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        size_t functionCallCount = a_ctx->dynamicAnalyzer->getFunctionCallCount();
        
        // 🔥 Taint 개수 확인
        size_t taintCount = 0;
        if (a_ctx->chainTrackerManager && a_ctx->chainTrackerManager->getTaintTracker()) {
            taintCount = a_ctx->chainTrackerManager->getTaintTracker()->getTaintCount();
        }
        
        std::map<std::string, JsValue> eventMetadata;
        eventMetadata["url"] = JsValue(url);
        eventMetadata["method"] = JsValue(method);
        if (!body.empty()) {
            eventMetadata["body"] = JsValue(body.substr(0, (std::min)((size_t)200, body.length())));
        }
        eventMetadata["function_call_count"] = JsValue(static_cast<double>(functionCallCount));
        eventMetadata["taint_count"] = JsValue(static_cast<double>(taintCount));
        
        bool hasSensitiveData = false;
        std::string lowerBody = body;
        std::transform(lowerBody.begin(), lowerBody.end(), lowerBody.begin(), ::tolower);
        if (lowerBody.find("password") != std::string::npos ||
            lowerBody.find("credential") != std::string::npos ||
            lowerBody.find("token") != std::string::npos ||
            lowerBody.find("auth") != std::string::npos) {
            hasSensitiveData = true;
            eventMetadata["sensitive"] = JsValue(true);
        }
        
        // 🚨 조건 체크: 1000번 이상 함수 호출 OR 100개 이상 Taint 값
        bool excessive_calls = functionCallCount >= 1000;
        bool excessive_taints = taintCount >= 100;
        
        // 🎯 0점에서 시작하는 가점 기반 severity 계산
        int finalSeverity = 0;  // 기본 0점 (XHR 자체는 정상 동작)
        int finalStatus = 0;
        
        // 1. 민감 데이터 포함 (+3점)
        if (hasSensitiveData) {
            finalSeverity += 3;
            eventMetadata["threat_sensitive_data"] = JsValue(true);
        }
        
        // 2. 과도한 호출 (+2점)
        if (excessive_calls) {
            finalSeverity += 2;
            finalStatus = 1;
            eventMetadata["excessive_function_calls"] = JsValue(true);
            printf("[ALERT] Excessive XHR calls! Function call count: %zu (>= 1000)\n", functionCallCount);
        }
        
        // 3. 과도한 Taint (+2점)
        if (excessive_taints) {
            finalSeverity += 2;
            finalStatus = 1;
            eventMetadata["excessive_taints"] = JsValue(true);
            printf("[ALERT] Excessive taint values! Taint count: %zu (>= 100)\n", taintCount);
        }
        
        // 4. 외부/의심 도메인 체크 (+2점)
        std::string lowerUrl = url;
        std::transform(lowerUrl.begin(), lowerUrl.end(), lowerUrl.begin(), ::tolower);
        bool suspiciousDomain = (
            lowerUrl.find("http://") == 0 ||  // HTTP (비암호화)
            lowerUrl.find(".ru") != std::string::npos ||
            lowerUrl.find(".cn") != std::string::npos ||
            std::count(lowerUrl.begin(), lowerUrl.end(), '.') > 3  // 서브도메인 과다
        );
        if (suspiciousDomain) {
            finalSeverity += 2;
            eventMetadata["suspicious_domain"] = JsValue(true);
        }
        
        // 5. 데이터 인코딩/난독화 체크 (+1점)
        if (!body.empty()) {
            std::string lowerBody = body;
            std::transform(lowerBody.begin(), lowerBody.end(), lowerBody.begin(), ::tolower);
            if (lowerBody.find("btoa") != std::string::npos ||
                lowerBody.find("atob") != std::string::npos ||
                lowerBody.find("base64") != std::string::npos) {
                finalSeverity += 1;
                eventMetadata["contains_encoding"] = JsValue(true);
            }
        }
        
        // 최종 점수 제한 (0~10)
        finalSeverity = std::min(finalSeverity, 10);
        
        if (finalSeverity >= 6) {
            printf("[ALERT] High risk XHR detected! URL: %s, Method: %s, Score: %d\n", 
                   url.c_str(), method.c_str(), finalSeverity);
        }
        
        // HookEvent 생성 - 생성자 사용
        HookEvent xhrEvent(
            HookType::FETCH_REQUEST,
            "XMLHttpRequest",
            std::vector<JsValue>{ JsValue(url), JsValue(method) },
            JsValue(std::monostate()),
            eventMetadata,
            finalSeverity
        );
        
        // status 설정
        xhrEvent.status = finalStatus;
        
        a_ctx->dynamicAnalyzer->recordEvent(xhrEvent);
    }
}

void XMLHTTPRequestObject::simulateResponse() {
    try {
        this->responseText = generateMockResponse();
        this->status = 200;
        this->readyState = 2; // HEADERS_RECEIVED
        triggerReadyStateChange();
        this->readyState = 3; // LOADING
        triggerReadyStateChange();
        this->readyState = 4; // DONE
        triggerReadyStateChange();
    } catch (const std::exception& e) {
        std::cerr << "[XHR] Error simulating response: " << e.what() << std::endl;
    }
}

std::string XMLHTTPRequestObject::generateMockResponse() {
    std::string lowerUrl = url;
    std::transform(lowerUrl.begin(), lowerUrl.end(), lowerUrl.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    if (lowerUrl.find("login") != std::string::npos || lowerUrl.find("auth") != std::string::npos) {
        return "{\"status\":\"success\",\"token\":\"mock_auth_token_12345\"}";
    } else if (lowerUrl.find("api") != std::string::npos || lowerUrl.find("data") != std::string::npos) {
        return "{\"status\":\"success\",\"data\":[{\"id\":1,\"name\":\"test\"}]}";
    } else {
        return "{\"status\":\"ok\"}";
    }
}

void XMLHTTPRequestObject::triggerReadyStateChange() {
    // 🔥 콜백 유효성 검사 강화
    if (!ctx || JS_IsUndefined(onreadystatechangeCallback) || 
        !JS_IsFunction(ctx, onreadystatechangeCallback)) {
        return;
    }
    
    JSValue global_obj = JS_GetGlobalObject(ctx);
    if (JS_IsException(global_obj)) {
        return;
    }
    
    JSValue ret_val = JS_Call(ctx, onreadystatechangeCallback, global_obj, 0, nullptr);
    JS_FreeValue(ctx, global_obj);
    
    // 🔥 예외 처리 수정 - Double-Free 방지
    if (JS_IsException(ret_val)) {
        JSValue exception = JS_GetException(ctx);
        if (!JS_IsUndefined(exception) && !JS_IsNull(exception)) {
            const char* error_msg = JS_ToCString(ctx, exception);
            if (error_msg) {
                std::cerr << "Error in onreadystatechange callback: " << error_msg << std::endl;
                JS_FreeCString(ctx, error_msg);
            }
        }
        JS_FreeValue(ctx, exception);
        // ret_val은 JS_EXCEPTION이므로 해제 안 함
    } else {
        // 정상 반환값만 해제
        JS_FreeValue(ctx, ret_val);
    }
}

// ============================================
// 🔥 QuickJS 등록 함수 (JSAnalyzer에서 호출)
// ============================================

// Finalizer
static void xhr_finalizer(JSRuntime* rt, JSValue val) {
    struct RuntimeClassIDs {
        JSClassID xhr_class_id;
        JSClassID activex_class_id;
    };
    
    RuntimeClassIDs* classIDs = static_cast<RuntimeClassIDs*>(JS_GetRuntimeOpaque(rt));
    if (!classIDs) return;
    
    XMLHTTPRequestObject* xhr = static_cast<XMLHTTPRequestObject*>(
        JS_GetOpaque(val, classIDs->xhr_class_id)
    );
    if (xhr) {
        // 🔥 CRITICAL: Finalizer는 JS_FreeRuntime() 중에 호출됨
        // 이 시점에서는 Context가 이미 해제되어 JS_FreeValue()를 안전하게 호출할 수 없음
        // QuickJS GC가 자동으로 모든 JSValue를 정리하므로 여기서는 C++ 객체만 삭제
        xhr->ctx = nullptr;
        xhr->onreadystatechangeCallback = JS_UNDEFINED;
        delete xhr;
    }
}

// Constructor
static JSValue xhr_constructor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv) {
    struct RuntimeClassIDs {
        JSClassID xhr_class_id;
        JSClassID activex_class_id;
    };
    
    JSRuntime* rt = JS_GetRuntime(ctx);
    RuntimeClassIDs* classIDs = static_cast<RuntimeClassIDs*>(JS_GetRuntimeOpaque(rt));
    if (!classIDs) return JS_EXCEPTION;
    
    JSValue obj = JS_NewObjectClass(ctx, classIDs->xhr_class_id);
    if (JS_IsException(obj)) return obj;
    
    JSAnalyzerContext* a_ctx = static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
    XMLHTTPRequestObject* xhr = new XMLHTTPRequestObject(ctx, a_ctx);
    JS_SetOpaque(obj, xhr);
    return obj;
}

// Getter/Setter 함수들
static JSValue js_xhr_get_readyState(JSContext* ctx, JSValueConst this_val) {
    XMLHTTPRequestObject* xhr = XMLHTTPRequestObject::getThis(ctx, this_val);
    if (!xhr) return JS_EXCEPTION;
    return JS_NewInt32(ctx, xhr->getReadyState());
}

static JSValue js_xhr_get_status(JSContext* ctx, JSValueConst this_val) {
    XMLHTTPRequestObject* xhr = XMLHTTPRequestObject::getThis(ctx, this_val);
    if (!xhr) return JS_EXCEPTION;
    return JS_NewInt32(ctx, xhr->getStatus());
}

static JSValue js_xhr_get_responseText(JSContext* ctx, JSValueConst this_val) {
    XMLHTTPRequestObject* xhr = XMLHTTPRequestObject::getThis(ctx, this_val);
    if (!xhr) return JS_EXCEPTION;
    return JS_NewString(ctx, xhr->getResponseText().c_str());
}

static JSValue js_xhr_get_onreadystatechange(JSContext* ctx, JSValueConst this_val) {
    XMLHTTPRequestObject* xhr = XMLHTTPRequestObject::getThis(ctx, this_val);
    if (!xhr) return JS_EXCEPTION;
    return JS_DupValue(ctx, xhr->onreadystatechangeCallback);
}

static JSValue js_xhr_set_onreadystatechange(JSContext* ctx, JSValueConst this_val, JSValue val) {
    XMLHTTPRequestObject* xhr = XMLHTTPRequestObject::getThis(ctx, this_val);
    if (!xhr) return JS_EXCEPTION;
    xhr->setOnReadyStateChange(val);
    return JS_UNDEFINED;
}

// 통합 등록 함수
void XMLHTTPRequestObject::registerClass(JSContext* ctx, JSRuntime* rt, JSValue global_obj, JSClassID class_id) {
    // 클래스 정의
    JSClassDef js_xhr_class = {
        .class_name = "XMLHttpRequest",
        .finalizer = xhr_finalizer,
    };
    JS_NewClass(rt, class_id, &js_xhr_class);
    
    // Prototype 생성
    JSValue xhr_proto = JS_NewObject(ctx);
    
    // 메서드 등록
    const JSCFunctionListEntry js_xhr_proto_funcs[] = {
        JS_CFUNC_DEF("open", 2, XMLHTTPRequestObject::js_open),
        JS_CFUNC_DEF("send", 1, XMLHTTPRequestObject::js_send),
        JS_CFUNC_DEF("setRequestHeader", 2, XMLHTTPRequestObject::js_setRequestHeader),
    };
    JS_SetPropertyFunctionList(ctx, xhr_proto, js_xhr_proto_funcs, 
        sizeof(js_xhr_proto_funcs) / sizeof(js_xhr_proto_funcs[0]));
    
    // 프로퍼티 등록
    const JSCFunctionListEntry js_xhr_proto_props[] = {
        JS_CGETSET_DEF("readyState", js_xhr_get_readyState, nullptr),
        JS_CGETSET_DEF("status", js_xhr_get_status, nullptr),
        JS_CGETSET_DEF("responseText", js_xhr_get_responseText, nullptr),
        JS_CGETSET_DEF("onreadystatechange", js_xhr_get_onreadystatechange, js_xhr_set_onreadystatechange),
    };
    JS_SetPropertyFunctionList(ctx, xhr_proto, js_xhr_proto_props, 
        sizeof(js_xhr_proto_props) / sizeof(js_xhr_proto_props[0]));
    
    // Constructor 생성 및 등록
    JSValue xhr_constructor_func = JS_NewCFunction2(ctx, xhr_constructor, 
                                                     "XMLHttpRequest", 0, 
                                                     JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, xhr_constructor_func, xhr_proto);
    JS_SetPropertyStr(ctx, global_obj, "XMLHttpRequest", xhr_constructor_func);
}
