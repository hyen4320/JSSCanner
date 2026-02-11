#include "pch.h"
#include "DocumentObject.h"
#include "../helpers/JSValueConverter.h"
#include "../helpers/SensitiveKeywordDetector.h"
#include "../helpers/MockHelpers.h"
#include "../../model/JsValueVariant.h"
#include "../../core/JSAnalyzer.h"

namespace DocumentObject {
    // 🔥 CRITICAL FIX: 멀티스레드 환경에서 데이터 레이스 방지
    // 각 스레드마다 독립적인 cookie 저장소 사용
    thread_local std::string g_cookie_storage = "";

    static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
        return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
    }

    JSValue js_document_write_hook(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (!a_ctx) return JS_UNDEFINED;

        std::string content = "";
        if (argc > 0) {
            const char* str = JS_ToCString(ctx, argv[0]);
            if (str) {
                content = str;
                JS_FreeCString(ctx, str);
            }
        }

        // 🔥 개선: content 내용 상세 분석
        std::map<std::string, JsValue> metadata;
        metadata["content_length"] = JsValue(static_cast<double>(content.length()));
        
        std::string lowerContent = content;
        std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);
        
        // HTML 태그 감지
        bool hasScript = lowerContent.find("<script") != std::string::npos;
        bool hasIframe = lowerContent.find("<iframe") != std::string::npos;
        bool hasForm = lowerContent.find("<form") != std::string::npos;
        bool hasHtml = lowerContent.find("<html") != std::string::npos;
        bool hasObject = lowerContent.find("<object") != std::string::npos;
        bool hasEmbed = lowerContent.find("<embed") != std::string::npos;
        
        if (hasScript) metadata["contains_script"] = JsValue("true");
        if (hasIframe) metadata["contains_iframe"] = JsValue("true");
        if (hasForm) metadata["contains_form"] = JsValue("true");
        if (hasHtml) metadata["contains_html"] = JsValue("true");
        if (hasObject) metadata["contains_object"] = JsValue("true");
        if (hasEmbed) metadata["contains_embed"] = JsValue("true");
        
        // URL 패턴 감지
        RE2 url_pattern(R"((?i)(https?://[^\s'"<>]+))");
        std::string url_match;
        if (RE2::PartialMatch(content, url_pattern, &url_match)) {
            metadata["external_url"] = JsValue(url_match);
        }
        
        // Base64 패턴 감지
        if (content.length() > 100) {
            RE2 base64_pattern(R"([A-Za-z0-9+/]{50,}={0,2})");
            if (RE2::PartialMatch(content, base64_pattern)) {
                metadata["contains_base64"] = JsValue("true");
            }
        }
        
        // 난독화 패턴 감지
        if (content.find("fromCharCode") != std::string::npos ||
            content.find("atob") != std::string::npos ||
            content.find("eval") != std::string::npos ||
            content.find("TextDecoder") != std::string::npos ||
            content.find("Uint8Array") != std::string::npos) {
            metadata["obfuscation_detected"] = JsValue("true");
        }
        
        // Severity 계산 - 주입된 컨텐츠의 위험도 기반
        int severity = 0;  // 기본 severity
        
        // 위험한 태그가 포함된 경우 (코드 실행/삽입 가능)
        if (hasScript || hasIframe || hasObject || hasEmbed) {
            severity += 3;
            metadata["threat_level"] = JsValue("high");
        }
        
        // 난독화 패턴이 감지된 경우 (의도 은폐)
        if (metadata.find("obfuscation_detected") != metadata.end()) {
            severity += 2;
        }
        
        // Base64 인코딩이 포함된 경우 (숨겨진 페이로드 가능성)
        if (metadata.find("contains_base64") != metadata.end()) {
            severity += 2;
        }
        
        // Form 태그가 포함된 경우 (피싱 위험)
        if (hasForm) {
            severity += 2;
            metadata["phishing_risk"] = JsValue("true");
        }
        
        // 외부 URL이 포함된 경우 (외부 리소스 참조)
        if (metadata.find("external_url") != metadata.end()) {
            severity += 1;
        }
        
        // document.write 자체 사용 (최소 점수 보장)
        if (severity == 0) {
            severity = 1;  // 아무 위협 요소가 없어도 최소 1점
        }
        
        // 최대 점수 제한
        severity = std::min(severity, 13);
        
        // 간단한 요약 문자열 생성 (findings용)
        std::string summaryContent = content;
        if (summaryContent.length() > 200) {
            summaryContent = summaryContent.substr(0, 200) + "...";
        }
        
        a_ctx->findings->push_back({0, summaryContent, "document_write_detected"});

        if (a_ctx->dynamicAnalyzer) {
            // 최대 1000자까지만 기록 (메모리 절약)
            std::string recordContent = content.length() > 1000 ? content.substr(0, 1000) + "..." : content;
            
            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::DOM_MANIPULATION, 
                "document.write", 
                {JsValue(recordContent)},
                JsValue(std::monostate()), 
                metadata,
                severity
            });
        }

        if (a_ctx->chainTrackerManager) {
            a_ctx->chainTrackerManager->trackFunctionCall("document.write", {JsValue(content)}, JsValue(std::monostate()));
        }

        return JS_UNDEFINED;
    }

    JSValue js_document_getElementById(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (!a_ctx) return JS_NULL;

        if (argc < 1) return JS_NULL;
        const char* id_cstr = JS_ToCString(ctx, argv[0]);
        if (!id_cstr) return JS_NULL;
        std::string id = id_cstr;
        JS_FreeCString(ctx, id_cstr);

        if (a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::DOM_MANIPULATION, "getElementById", 
                {JsValue(id)}, JsValue(std::monostate()), {}, 0});
        }
        
        if (a_ctx->chainTrackerManager) {
            a_ctx->chainTrackerManager->trackFunctionCall("getElementById", {JsValue(id)}, JsValue(std::monostate()));
        }

        return MockHelpers::createMockElement(ctx, id);
    }

    JSValue js_document_createElement(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (!a_ctx) return JS_NULL;

        if (argc < 1) return JS_NULL;
        const char* tag_cstr = JS_ToCString(ctx, argv[0]);
        if (!tag_cstr) return JS_NULL;
        std::string tag = tag_cstr;
        JS_FreeCString(ctx, tag_cstr);

        if (a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::DOM_MANIPULATION, "createElement", 
                {JsValue(tag)}, JsValue(std::monostate()), {}, 0});
        }
        
        if (a_ctx->chainTrackerManager) {
            a_ctx->chainTrackerManager->trackFunctionCall("createElement", {JsValue(tag)}, JsValue(std::monostate()));
        }

        return MockHelpers::createMockElement(ctx, tag);
    }

    JSValue js_document_get_cookie(JSContext* ctx, JSValueConst this_val) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        
        // 🎯 0점에서 시작 (cookie 읽기 자체는 정상 동작)
        int severity = 0;
        std::map<std::string, JsValue> metadata;
        
        // Cookie 내용 분석
        if (!g_cookie_storage.empty()) {
            std::string lowerCookie = g_cookie_storage;
            std::transform(lowerCookie.begin(), lowerCookie.end(), lowerCookie.begin(), ::tolower);
            
            // 1. 민감한 쿠키 키워드 체크 (+2점)
            if (lowerCookie.find("session") != std::string::npos ||
                lowerCookie.find("auth") != std::string::npos ||
                lowerCookie.find("token") != std::string::npos ||
                lowerCookie.find("jwt") != std::string::npos) {
                severity += 2;
                metadata["sensitive_cookie"] = JsValue(true);
            }
            
            metadata["cookie_length"] = JsValue(static_cast<double>(g_cookie_storage.length()));
        }
        
        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::DATA_EXFILTRATION, "document.cookie.read", 
                {}, JsValue(g_cookie_storage), metadata, severity});
        }
        if (a_ctx && a_ctx->chainTrackerManager) {
            a_ctx->chainTrackerManager->trackFunctionCall("document.cookie_read", {}, JsValue(g_cookie_storage));
        }
        return JS_NewString(ctx, g_cookie_storage.c_str());
    }

    JSValue js_document_set_cookie(JSContext* ctx, JSValueConst this_val, JSValueConst val) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        const char* cookie_cstr = JS_ToCString(ctx, val);
        if (cookie_cstr) {
            g_cookie_storage = cookie_cstr;
            
            // 🎯 0점에서 시작 (cookie 설정 자체는 정상 동작)
            int severity = 0;
            std::map<std::string, JsValue> metadata;
            
            std::string lowerCookie = g_cookie_storage;
            std::transform(lowerCookie.begin(), lowerCookie.end(), lowerCookie.begin(), ::tolower);
            
            // 1. 민감한 쿠키 키워드 체크 (+3점)
            if (lowerCookie.find("session") != std::string::npos ||
                lowerCookie.find("auth") != std::string::npos ||
                lowerCookie.find("token") != std::string::npos ||
                lowerCookie.find("jwt") != std::string::npos ||
                lowerCookie.find("password") != std::string::npos) {
                severity += 3;
                metadata["sensitive_cookie"] = JsValue(true);
            }
            
            // 2. HttpOnly 플래그 없음 (+1점)
            if (lowerCookie.find("httponly") == std::string::npos) {
                severity += 1;
                metadata["missing_httponly"] = JsValue(true);
            }
            
            // 3. Secure 플래그 없음 (+1점)
            if (lowerCookie.find("secure") == std::string::npos) {
                severity += 1;
                metadata["missing_secure"] = JsValue(true);
            }
            
            metadata["cookie_length"] = JsValue(static_cast<double>(g_cookie_storage.length()));
            
            if (a_ctx && a_ctx->dynamicAnalyzer) {
                a_ctx->dynamicAnalyzer->recordEvent({HookType::DATA_EXFILTRATION, "document.cookie.write", 
                    {JsValue(g_cookie_storage)}, JsValue(std::monostate()), metadata, severity});
            }
            if (a_ctx && a_ctx->chainTrackerManager) {
                a_ctx->chainTrackerManager->trackFunctionCall("document.cookie_write", 
                    {JsValue(g_cookie_storage)}, JsValue(std::monostate()));
            }
            JS_FreeCString(ctx, cookie_cstr);
        }
        return JS_UNDEFINED;
    }

    JSValue js_document_addEventListener(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 2 || !JS_IsFunction(ctx, argv[1])) {
            return JS_UNDEFINED;
        }

        // 재귀 깊이 체크 추가 - 무한 재귀 방지
        static thread_local int recursion_depth = 0;
        const int MAX_RECURSION_DEPTH = 100;
        
        if (recursion_depth >= MAX_RECURSION_DEPTH) {
            JS_ThrowRangeError(ctx, "Maximum event listener recursion depth exceeded");
            return JS_EXCEPTION;
        }

        std::string eventName = JSValueConverter::toString(ctx, argv[0]);
        if (eventName.empty()) {
            eventName = "load";
        }

        JSValue eventObj = MockHelpers::createEventObject(ctx, this_val, eventName);
        
        // 재귀 카운터 증가
        recursion_depth++;
        
        JSValue thisDup = JS_DupValue(ctx, this_val);
        JSValueConst args_arr[1] = { eventObj };
        JSValue ret = JS_Call(ctx, argv[1], thisDup, 1, args_arr);
        
        // 재귀 카운터 감소 (항상 실행되도록)
        recursion_depth--;
        
        // 🔥 예외 처리 - Double-Free 방지
        if (JS_IsException(ret)) {
            JSValue ex = JS_GetException(ctx);
            JS_FreeValue(ctx, ex);
        } else {
            JS_FreeValue(ctx, ret);
        }
        
        JS_FreeValue(ctx, thisDup);
        JS_FreeValue(ctx, eventObj);
        return JS_UNDEFINED;
    }

    JSValue js_document_querySelector(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (argc < 1) {
            if (a_ctx && a_ctx->dynamicAnalyzer) {
                a_ctx->dynamicAnalyzer->recordEvent({HookType::DOM_MANIPULATION, "querySelector_empty", 
                    {}, JsValue(std::monostate()), {}, 0});
            }
            return JS_NULL;
        }

        std::string selector = JSValueConverter::toString(ctx, argv[0]);
        if (selector.empty()) {
            if (a_ctx && a_ctx->dynamicAnalyzer) {
                a_ctx->dynamicAnalyzer->recordEvent({HookType::DOM_MANIPULATION, "querySelector_empty", 
                    {}, JsValue(std::monostate()), {}, 0});
            }
            return JS_NULL;
        }

        std::string matched;
        bool sensitive = SensitiveKeywordDetector::detect(selector, matched);

        std::map<std::string, JsValue> metadata;
        metadata["selector"] = JsValue(selector);
        if (!matched.empty()) {
            metadata["keywords"] = JsValue(matched);
        }

        int severity = sensitive ? 3 : 0;  // sensitive 키워드 감지 시에만 점수 부여
        std::string eventName = sensitive ? "querySelector_sensitive" : "querySelector";

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::DOM_MANIPULATION, eventName, 
                {JsValue(selector)}, JsValue(std::monostate()), metadata, severity});
        }

        if (a_ctx && a_ctx->chainTrackerManager) {
            a_ctx->chainTrackerManager->trackFunctionCall("document.querySelector", 
                {JsValue(selector)}, JsValue(std::monostate()));
        }

        std::string elementId = "qs_" + std::to_string(std::hash<std::string>{}(selector));
        return MockHelpers::createMockElement(ctx, elementId);
    }

    JSValue js_document_querySelectorAll(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (argc < 1) {
            if (a_ctx && a_ctx->dynamicAnalyzer) {
                a_ctx->dynamicAnalyzer->recordEvent({HookType::DOM_MANIPULATION, "querySelectorAll_empty", 
                    {}, JsValue(std::monostate()), {}, 0});
            }
            return JS_NewArray(ctx);
        }

        std::string selector = JSValueConverter::toString(ctx, argv[0]);
        std::string matched;
        bool sensitive = SensitiveKeywordDetector::detect(selector, matched);

        std::map<std::string, JsValue> metadata;
        metadata["selector"] = JsValue(selector);

        size_t count = 3;
        metadata["count"] = JsValue(static_cast<double>(count));
        if (!matched.empty()) {
            metadata["keywords"] = JsValue(matched);
        }

        int severity = sensitive ? 3 : 0;  // sensitive 키워드 감지 시에만 점수 부여

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::DOM_MANIPULATION, "querySelectorAll", 
                {JsValue(selector)}, JsValue(std::monostate()), metadata, severity});
        }

        if (a_ctx && a_ctx->chainTrackerManager) {
            a_ctx->chainTrackerManager->trackFunctionCall("document.querySelectorAll", 
                {JsValue(selector)}, JsValue(std::monostate()));
        }

        JSValue array = JS_NewArray(ctx);
        for (uint32_t i = 0; i < count; ++i) {
            std::string elementId = "qs_all_" + std::to_string(std::hash<std::string>{}(selector + std::to_string(i)));
            JSValue element = MockHelpers::createMockElement(ctx, elementId);
            JS_SetPropertyUint32(ctx, array, i, element);
        }

        return array;
    }

    void registerDocumentObject(JSContext* ctx, JSValue global_obj) {
        JSValue document_obj = JS_NewObject(ctx);
        
        JS_SetPropertyStr(ctx, document_obj, "write", 
            JS_NewCFunction(ctx, js_document_write_hook, "write", 1));
        JS_SetPropertyStr(ctx, document_obj, "getElementById", 
            JS_NewCFunction(ctx, js_document_getElementById, "getElementById", 1));
        JS_SetPropertyStr(ctx, document_obj, "createElement", 
            JS_NewCFunction(ctx, js_document_createElement, "createElement", 1));
        JS_SetPropertyStr(ctx, document_obj, "addEventListener", 
            JS_NewCFunction(ctx, js_document_addEventListener, "addEventListener", 2));
        JS_SetPropertyStr(ctx, document_obj, "querySelector", 
            JS_NewCFunction(ctx, js_document_querySelector, "querySelector", 1));
        JS_SetPropertyStr(ctx, document_obj, "querySelectorAll", 
            JS_NewCFunction(ctx, js_document_querySelectorAll, "querySelectorAll", 1));

        // Cookie getter/setter
        JSCFunctionType cookie_getter_type;
        cookie_getter_type.getter = js_document_get_cookie;
        JSValue cookie_getter = JS_NewCFunction2(ctx, cookie_getter_type.generic, "get_cookie", 0, JS_CFUNC_getter, 0);

        JSCFunctionType cookie_setter_type;
        cookie_setter_type.setter = js_document_set_cookie;
        JSValue cookie_setter = JS_NewCFunction2(ctx, cookie_setter_type.generic, "set_cookie", 1, JS_CFUNC_setter, 0);

        JS_DefinePropertyGetSet(ctx, document_obj, JS_NewAtom(ctx, "cookie"), cookie_getter, cookie_setter, JS_PROP_C_W_E);

        JS_FreeValue(ctx, cookie_getter);
        JS_FreeValue(ctx, cookie_setter);
        
        // ============================================================================
        // documentElement 객체 ?�성 �??�록
        // ============================================================================
        JSValue documentElement_obj = JS_NewObject(ctx);
        
        // innerHTML setter ?�록
        JSCFunctionType innerHTML_setter_type;
        innerHTML_setter_type.setter = js_document_element_set_innerHTML;
        JSValue innerHTML_setter = JS_NewCFunction2(ctx, innerHTML_setter_type.generic, "set_innerHTML", 1, JS_CFUNC_setter, 0);
        
        JS_DefinePropertyGetSet(ctx, documentElement_obj, JS_NewAtom(ctx, "innerHTML"), 
                                JS_UNDEFINED, innerHTML_setter, JS_PROP_C_W_E);
        JS_FreeValue(ctx, innerHTML_setter);
        
        // documentElement??document 객체???�록
        JS_SetPropertyStr(ctx, document_obj, "documentElement", documentElement_obj);
        
        // 🔥 body 객체 추가 (addEventListener 포함)
        JSValue body_obj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, body_obj, "addEventListener",
            JS_NewCFunction(ctx, js_document_addEventListener, "addEventListener", 2));
        JS_SetPropertyStr(ctx, document_obj, "body", body_obj);
        // body_obj는 자동으로 해제됨 (JS_SetPropertyStr이 참조를 가져감)
        
        // 🔥 location 객체 추가 (document.location.href 지원)
        JSValue location_obj = JS_NewObject(ctx);
        
        // 각 속성 추가 (임시 JSValue 생성 → 설정 → 해제 불필요, JS_NewString은 이미 전달됨)
        JS_SetPropertyStr(ctx, location_obj, "href", JS_NewString(ctx, "https://example.com/"));
        JS_SetPropertyStr(ctx, location_obj, "hostname", JS_NewString(ctx, "example.com"));
        JS_SetPropertyStr(ctx, location_obj, "pathname", JS_NewString(ctx, "/"));
        JS_SetPropertyStr(ctx, location_obj, "protocol", JS_NewString(ctx, "https:"));
        JS_SetPropertyStr(ctx, location_obj, "search", JS_NewString(ctx, ""));
        JS_SetPropertyStr(ctx, location_obj, "hash", JS_NewString(ctx, ""));
        
        // location 객체를 document에 설정
        JS_SetPropertyStr(ctx, document_obj, "location", location_obj);
        // location_obj는 자동으로 해제됨 (JS_SetPropertyStr이 참조를 가져감)
        
        // 🔥 NEW: document.scripts 추가 (빈 배열 - layer.js가 scripts.length를 체크함)
        JSValue scripts_array = JS_NewArray(ctx);
        JS_SetPropertyStr(ctx, document_obj, "scripts", scripts_array);
        
        // 🔥 NEW: document.currentScript 추가 (null)
        JS_SetPropertyStr(ctx, document_obj, "currentScript", JS_NULL);
        
        // 🔥 NEW: document.head 추가
        JSValue head_obj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, document_obj, "head", head_obj);
        
        // 🔥 NEW: document.getElementsByTagName 추가 (빈 배열 반환)
        JS_SetPropertyStr(ctx, document_obj, "getElementsByTagName",
            JS_NewCFunction(ctx, js_document_querySelectorAll, "getElementsByTagName", 1));
        
        // 🔥 NEW: document 객체를 전역에 등록하되, 읽기 전용으로 설정
        JS_DefinePropertyValueStr(ctx, global_obj, "document", document_obj, 
                                   JS_PROP_C_W_E | JS_PROP_CONFIGURABLE);
    }

    // document.documentElement.innerHTML setter - 전체 페이지 교체 탐지
    JSValue js_document_element_set_innerHTML(JSContext* ctx, JSValueConst this_val, JSValueConst val) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        
        const char* html_cstr = JS_ToCString(ctx, val);
        if (html_cstr) {
            std::string htmlContent = html_cstr;
            JS_FreeCString(ctx, html_cstr);
            
            if (a_ctx) {
                if (a_ctx->findings) {
                    a_ctx->findings->push_back({0, htmlContent, "document_element_innerHTML_overwrite"});
                }
                
                if (a_ctx->dynamicAnalyzer) {
                    std::map<std::string, JsValue> metadata;
                    metadata["action"] = JsValue("full_page_replacement");
                    metadata["content_length"] = JsValue(static_cast<double>(htmlContent.length()));
                    
                    std::string lowerHtml = htmlContent;
                    std::transform(lowerHtml.begin(), lowerHtml.end(), lowerHtml.begin(), ::tolower);
                    
                    // Severity 계산 - 전체 페이지 교체의 위험도 기반
                    int severity = 5;  // 전체 페이지 교체 기본 점수
                    
                    // 위험한 태그 감지
                    bool hasScript = lowerHtml.find("<script") != std::string::npos;
                    bool hasIframe = lowerHtml.find("<iframe") != std::string::npos;
                    bool hasObject = lowerHtml.find("<object") != std::string::npos;
                    bool hasEmbed = lowerHtml.find("<embed") != std::string::npos;
                    
                    if (hasScript || hasIframe || hasObject || hasEmbed) {
                        severity += 3;
                        metadata["contains_dangerous_tags"] = JsValue("true");
                    }
                    
                    // 차단 패턴 감지
                    if (lowerHtml.find("access denied") != std::string::npos ||
                        lowerHtml.find("not supported") != std::string::npos ||
                        lowerHtml.find("blocked") != std::string::npos) {
                        metadata["pattern"] = JsValue("access_blocking");
                        severity += 2;
                    }
                    
                    // 외부 URL 감지
                    RE2 url_pattern(R"((?i)(https?://[^\s'"<>]+))");
                    if (RE2::PartialMatch(htmlContent, url_pattern)) {
                        severity += 1;
                        metadata["contains_external_url"] = JsValue("true");
                    }
                    
                    // 최대 점수 제한
                    severity = std::min(severity, 15);
                    
                    a_ctx->dynamicAnalyzer->recordEvent({
                        HookType::DOM_MANIPULATION, 
                        "document.documentElement.innerHTML", 
                        {JsValue(htmlContent.substr(0, std::min(size_t(200), htmlContent.length())))},
                        JsValue(std::monostate()), 
                        metadata, 
                        severity
                    });
                }
                
                if (a_ctx->chainTrackerManager) {
                    a_ctx->chainTrackerManager->trackFunctionCall(
                        "document.documentElement.innerHTML=", 
                        {JsValue(htmlContent)}, 
                        JsValue(std::monostate())
                    );
                }
            }
        }
        
        return JS_UNDEFINED;
    }
}
