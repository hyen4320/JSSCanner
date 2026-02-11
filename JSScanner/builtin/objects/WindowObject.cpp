#include "pch.h"
#include "WindowObject.h"
#include "../helpers/JSValueConverter.h"
#include "../helpers/SensitiveKeywordDetector.h"
#include "../../model/JsValueVariant.h"
#include "../../core/JSAnalyzer.h"

namespace WindowObject {
    // Forward declarations
    static JSValue createMockFetchResponse(JSContext* ctx, const std::string& url, const std::string& method,
        const std::string& bodySnippet, bool sensitive);
    static JSValue createMockFetchPromise(JSContext* ctx, const std::string& url, const std::string& method,
        const std::string& bodySnippet, bool sensitive);
    JSValue js_mock_response_text(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_mock_response_json(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);

    static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
        return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
    }

    // addEventListener mock - window용
    JSValue js_addEventListener(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        
        if (argc >= 1) {
            const char* event_type = JS_ToCString(ctx, argv[0]);
            if (event_type && a_ctx && a_ctx->findings) {
                std::string msg = "window.addEventListener: ";
                msg += event_type;
                a_ctx->findings->push_back({0, msg, "event_listener_api"});
                JS_FreeCString(ctx, event_type);
            }
        }
        
        return JS_UNDEFINED;
    }

    JSValue js_window_location_set_href(JSContext* ctx, JSValueConst this_val, JSValueConst val) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (!a_ctx) return JS_UNDEFINED;

        const char* url_cstr = JS_ToCString(ctx, val);
        if (url_cstr) {
            std::string url = url_cstr;
            a_ctx->findings->push_back({ 0, url, "window_location_href_set" });
            if (a_ctx->urlCollector) {
                a_ctx->urlCollector->addUrlWithMetadata(url, "location.href", 0);  // 🔥 MODIFIED
            }
            if (a_ctx->dynamicAnalyzer) {
                a_ctx->dynamicAnalyzer->recordEvent({ HookType::LOCATION_CHANGE, "location.href.set",
                    {JsValue(url)}, JsValue(std::monostate()), {}, 9 });
            }
            if (a_ctx->chainTrackerManager) {
                a_ctx->chainTrackerManager->trackFunctionCall("window.location.href=",
                    { JsValue(url) }, JsValue(std::monostate()));
            }
            JS_FreeCString(ctx, url_cstr);
        }
        return JS_UNDEFINED;
    }

    JSValue js_window_location_replace(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (!a_ctx) return JS_UNDEFINED;

        if (argc > 0) {
            const char* url_cstr = JS_ToCString(ctx, argv[0]);
            if (url_cstr) {
                std::string url = url_cstr;
                a_ctx->findings->push_back({ 0, url, "window_location_replace_call" });
                if (a_ctx->urlCollector) {
                    a_ctx->urlCollector->addUrlWithMetadata(url, "location.replace", 0);  // 🔥 MODIFIED
                }
                if (a_ctx->dynamicAnalyzer) {
                    a_ctx->dynamicAnalyzer->recordEvent({ HookType::LOCATION_CHANGE, "location.replace",
                        {JsValue(url)}, JsValue(std::monostate()), {}, 9 });
                }
                if (a_ctx->chainTrackerManager) {
                    a_ctx->chainTrackerManager->trackFunctionCall("window.location.replace",
                        { JsValue(url) }, JsValue(std::monostate()));
                }
                JS_FreeCString(ctx, url_cstr);
            }
        }
        return JS_UNDEFINED;
    }

    JSValue js_window_location_assign(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (!a_ctx) return JS_UNDEFINED;

        if (argc > 0) {
            const char* url_cstr = JS_ToCString(ctx, argv[0]);
            if (url_cstr) {
                std::string url = url_cstr;
                a_ctx->findings->push_back({ 0, url, "window_location_assign_call" });
                if (a_ctx->urlCollector) {
                    a_ctx->urlCollector->addUrlWithMetadata(url, "location.assign", 0);  // 🔥 MODIFIED
                }
                if (a_ctx->dynamicAnalyzer) {
                    a_ctx->dynamicAnalyzer->recordEvent({ HookType::LOCATION_CHANGE, "location.assign",
                        {JsValue(url)}, JsValue(std::monostate()), {}, 9 });
                }
                if (a_ctx->chainTrackerManager) {
                    a_ctx->chainTrackerManager->trackFunctionCall("window.location.assign",
                        { JsValue(url) }, JsValue(std::monostate()));
                }
                JS_FreeCString(ctx, url_cstr);
            }
        }
        return JS_UNDEFINED;
    }

    // ✅ Navigator getter (올바른 시그니처)
    JSValue js_navigator_get_userAgent(JSContext* ctx, JSValueConst this_val) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        // 🔥 BrowserConfig에서 userAgent 가져오기
        std::string userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        
        if (a_ctx && a_ctx->browserConfig) {
            userAgent = a_ctx->browserConfig->userAgent;
        }

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::ENVIRONMENT_DETECTION,
                "navigator.userAgent",
                {},
                JsValue(userAgent),
                {},
                6
            });
        }

        return JS_NewString(ctx, userAgent.c_str());
    }

    // 🔥 추가 Navigator 속성들
    JSValue js_navigator_get_platform(JSContext* ctx, JSValueConst this_val) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        std::string platform = "Win32";
        if (a_ctx && a_ctx->browserConfig) {
            platform = a_ctx->browserConfig->platform;
        }
        return JS_NewString(ctx, platform.c_str());
    }

    JSValue js_navigator_get_vendor(JSContext* ctx, JSValueConst this_val) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        std::string vendor = "Google Inc.";
        if (a_ctx && a_ctx->browserConfig) {
            vendor = a_ctx->browserConfig->vendor;
        }
        return JS_NewString(ctx, vendor.c_str());
    }

    JSValue js_navigator_get_language(JSContext* ctx, JSValueConst this_val) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        std::string language = "en-US";
        if (a_ctx && a_ctx->browserConfig) {
            language = a_ctx->browserConfig->language;
        }
        return JS_NewString(ctx, language.c_str());
    }

    JSValue js_navigator_get_hardwareConcurrency(JSContext* ctx, JSValueConst this_val) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        int hardwareConcurrency = 8;
        if (a_ctx && a_ctx->browserConfig) {
            hardwareConcurrency = a_ctx->browserConfig->hardwareConcurrency;
        }
        return JS_NewInt32(ctx, hardwareConcurrency);
    }

    JSValue js_navigator_get_deviceMemory(JSContext* ctx, JSValueConst this_val) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        long long deviceMemory = 8;
        if (a_ctx && a_ctx->browserConfig) {
            deviceMemory = a_ctx->browserConfig->deviceMemory;
        }
        return JS_NewInt64(ctx, deviceMemory);
    }

    JSValue js_navigator_get_maxTouchPoints(JSContext* ctx, JSValueConst this_val) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        int maxTouchPoints = 0;
        if (a_ctx && a_ctx->browserConfig) {
            maxTouchPoints = a_ctx->browserConfig->maxTouchPoints;
        }
        return JS_NewInt32(ctx, maxTouchPoints);
    }

    // 🔥 Screen 속성들
    JSValue js_screen_get_width(JSContext* ctx, JSValueConst this_val) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        int width = 1920;
        if (a_ctx && a_ctx->browserConfig) {
            width = a_ctx->browserConfig->screenWidth;
        }
        return JS_NewInt32(ctx, width);
    }

    JSValue js_screen_get_height(JSContext* ctx, JSValueConst this_val) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        int height = 1080;
        if (a_ctx && a_ctx->browserConfig) {
            height = a_ctx->browserConfig->screenHeight;
        }
        return JS_NewInt32(ctx, height);
    }

    JSValue js_screen_get_availWidth(JSContext* ctx, JSValueConst this_val) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        int availWidth = 1920;
        if (a_ctx && a_ctx->browserConfig) {
            availWidth = a_ctx->browserConfig->screenAvailWidth;
        }
        return JS_NewInt32(ctx, availWidth);
    }

    JSValue js_screen_get_availHeight(JSContext* ctx, JSValueConst this_val) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        int availHeight = 1040;
        if (a_ctx && a_ctx->browserConfig) {
            availHeight = a_ctx->browserConfig->screenAvailHeight;
        }
        return JS_NewInt32(ctx, availHeight);
    }

    JSValue js_screen_get_colorDepth(JSContext* ctx, JSValueConst this_val) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        int colorDepth = 24;
        if (a_ctx && a_ctx->browserConfig) {
            colorDepth = a_ctx->browserConfig->screenColorDepth;
        }
        return JS_NewInt32(ctx, colorDepth);
    }

    JSValue js_screen_get_pixelDepth(JSContext* ctx, JSValueConst this_val) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        int pixelDepth = 24;
        if (a_ctx && a_ctx->browserConfig) {
            pixelDepth = a_ctx->browserConfig->screenPixelDepth;
        }
        return JS_NewInt32(ctx, pixelDepth);
    }

    // ✅ Window getter (올바른 시그니처)
    JSValue js_window_get_innerWidth(JSContext* ctx, JSValueConst this_val) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        
        // 🔥 BrowserConfig에서 innerWidth 가져오기
        int innerWidth = 1920;  // 기본값
        
        if (a_ctx && a_ctx->browserConfig) {
            innerWidth = a_ctx->browserConfig->innerWidth;
        }
        
        return JS_NewInt32(ctx, innerWidth);
    }

    JSValue js_window_get_innerHeight(JSContext* ctx, JSValueConst this_val) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        
        // 🔥 BrowserConfig에서 innerHeight 가져오기
        int innerHeight = 1080;  // 기본값
        
        if (a_ctx && a_ctx->browserConfig) {
            innerHeight = a_ctx->browserConfig->innerHeight;
        }
        
        return JS_NewInt32(ctx, innerHeight);
    }

    static JSValue createMockFetchResponse(JSContext* ctx, const std::string& url, const std::string& method,
        const std::string& bodySnippet, bool sensitive) {
        JSValue response = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, response, "ok", JS_NewBool(ctx, 1));
        JS_SetPropertyStr(ctx, response, "status", JS_NewInt32(ctx, 200));
        JS_SetPropertyStr(ctx, response, "statusText", JS_NewString(ctx, "OK"));
        JS_SetPropertyStr(ctx, response, "url", JS_NewString(ctx, url.c_str()));
        JS_SetPropertyStr(ctx, response, "method", JS_NewString(ctx, method.c_str()));
        JS_SetPropertyStr(ctx, response, "sensitive", JS_NewBool(ctx, sensitive ? 1 : 0));
        JS_SetPropertyStr(ctx, response, "bodySnippet", JS_NewString(ctx, bodySnippet.c_str()));

        JS_SetPropertyStr(ctx, response, "text", JS_NewCFunction(ctx, js_mock_response_text, "text", 0));
        JS_SetPropertyStr(ctx, response, "json", JS_NewCFunction(ctx, js_mock_response_json, "json", 0));
        JS_SetPropertyStr(ctx, response, "clone", JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
            return JS_DupValue(ctx, this_val);
            }, "clone", 0));

        return response;
    }
    JSValue js_fetch(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        std::string url = argc >= 1 ? JSValueConverter::toString(ctx, argv[0]) : "";
        std::string method = "GET";
        std::string bodySnippet = "";
        bool hasSensitiveData = false;

        // 디버그: fetch 호출 확인
        // printf("[DEBUG] fetch() called with URL: %s\n", url.c_str());

        if (argc >= 2 && JS_IsObject(argv[1])) {
            JSValue method_val = JS_GetPropertyStr(ctx, argv[1], "method");
            if (!JS_IsException(method_val)) {
                std::string m = JSValueConverter::toString(ctx, method_val);
                if (!m.empty()) method = m;
            }
            JS_FreeValue(ctx, method_val);

            // printf("[DEBUG] fetch() method: %s\n", method.c_str());

            // body 파라미터 확인
            JSValue body_val = JS_GetPropertyStr(ctx, argv[1], "body");
            if (!JS_IsUndefined(body_val) && !JS_IsNull(body_val)) {
                bodySnippet = JSValueConverter::toString(ctx, body_val);
                // printf("[DEBUG] fetch() body: %s\n", bodySnippet.c_str());
                
                // 민감 데이터 확인
                std::string bodyLower = bodySnippet;
                std::transform(bodyLower.begin(), bodyLower.end(), bodyLower.begin(), ::tolower);
                if (bodyLower.find("password") != std::string::npos ||
                    bodyLower.find("credential") != std::string::npos ||
                    bodyLower.find("token") != std::string::npos ||
                    bodyLower.find("auth") != std::string::npos) {
                    hasSensitiveData = true;
                    printf("[DEBUG] Sensitive data detected!\n");
                }
            }
            JS_FreeValue(ctx, body_val);
        }

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            // 🔥 MODIFIED: 메타데이터 포함하여 URL 추가
            if (a_ctx->urlCollector) {
                a_ctx->urlCollector->addUrlWithMetadata(url, "fetch", 0);
            }
            
            // 🔥 함수 호출 횟수 확인 (fetch 호출 전)
            size_t functionCallCount = a_ctx->dynamicAnalyzer->getFunctionCallCount();
            
            // 🔥 Taint 개수 확인
            size_t taintCount = 0;
            if (a_ctx->chainTrackerManager && a_ctx->chainTrackerManager->getTaintTracker()) {
                taintCount = a_ctx->chainTrackerManager->getTaintTracker()->getTaintCount();
            }
            
            std::map<std::string, JsValue> metadata;
            metadata["url"] = JsValue(url);
            metadata["method"] = JsValue(method);
            if (!bodySnippet.empty()) {
                metadata["body"] = JsValue(bodySnippet);
            }
            if (hasSensitiveData) {
                metadata["sensitive"] = JsValue(true);
            }
            
            // 함수 호출 횟수 및 Taint 개수 메타데이터에 추가
            metadata["function_call_count"] = JsValue(static_cast<double>(functionCallCount));
            metadata["taint_count"] = JsValue(static_cast<double>(taintCount));
            
            // 🚨 조건 체크: 1000번 이상 함수 호출 OR 100개 이상 Taint 값
            bool excessive_calls = functionCallCount >= 1000;
            bool excessive_taints = taintCount >= 100;
            
            // severity 및 status 결정
            int finalSeverity = hasSensitiveData ? 9 : 7;
            int finalStatus = 0;
            
            if (excessive_calls || excessive_taints) {
                finalStatus = 1;
                finalSeverity = 10;  // 최고 위험도
                
                if (excessive_calls) {
                    metadata["excessive_function_calls"] = JsValue(true);
                    printf("[ALERT] Suspicious fetch detected! Function call count: %zu (>= 1000)\n", functionCallCount);
                }
                
                if (excessive_taints) {
                    metadata["excessive_taints"] = JsValue(true);
                    printf("[ALERT] Suspicious fetch detected! Taint count: %zu (>= 100)\n", taintCount);
                }
                
                printf("[ALERT] URL: %s, Method: %s\n", url.c_str(), method.c_str());
            }

            // HookEvent 생성 - 생성자 사용
            HookEvent fetchEvent(
                HookType::FETCH_REQUEST,
                "fetch",
                std::vector<JsValue>{ JsValue(url), JsValue(method) },
                JsValue(std::monostate()),
                metadata,
                finalSeverity
            );
            
            // status 설정
            fetchEvent.status = finalStatus;

            a_ctx->dynamicAnalyzer->recordEvent(fetchEvent);
        }

        // Promise를 반환하여 .then() 체이닝이 가능하도록 함
        return createMockFetchPromise(ctx, url, method, bodySnippet, hasSensitiveData);
    }

    JSValue js_mock_response_text(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        // Mock response.text() - Promise를 반환하여 문자열 반환
        JSValue resolvingFuncs[2];
        JSValue promise = JS_NewPromiseCapability(ctx, resolvingFuncs);
        if (JS_IsException(promise)) {
            return JS_NewString(ctx, "");
        }

        JSValue bodyVal = JS_GetPropertyStr(ctx, this_val, "bodySnippet");
        std::string body = JSValueConverter::toString(ctx, bodyVal);
        JS_FreeValue(ctx, bodyVal);

        JSValue textValue = JS_NewString(ctx, body.c_str());
        JSValue callResult = JS_Call(ctx, resolvingFuncs[0], JS_UNDEFINED, 1, &textValue);
        JS_FreeValue(ctx, callResult);  // 🔥 반환값 해제
        JS_FreeValue(ctx, textValue);
        JS_FreeValue(ctx, resolvingFuncs[0]);
        JS_FreeValue(ctx, resolvingFuncs[1]);
        return promise;
    }

    JSValue js_mock_response_json(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        // Mock response.json() - Promise를 반환하여 JSON 객체 반환
        JSValue resolvingFuncs[2];
        JSValue promise = JS_NewPromiseCapability(ctx, resolvingFuncs);
        if (JS_IsException(promise)) {
            return JS_NewObject(ctx);
        }

        JSValue bodyVal = JS_GetPropertyStr(ctx, this_val, "bodySnippet");
        std::string body = JSValueConverter::toString(ctx, bodyVal);
        JS_FreeValue(ctx, bodyVal);

        // JSON 파싱 시도
        JSValue jsonValue = JS_ParseJSON(ctx, body.c_str(), body.length(), "response.json");
        if (JS_IsException(jsonValue)) {
            // 파싱 실패 시 빈 객체 반환
            JSValue ex = JS_GetException(ctx);
            JS_FreeValue(ctx, ex);
            jsonValue = JS_NewObject(ctx);
        }

        JSValue callResult = JS_Call(ctx, resolvingFuncs[0], JS_UNDEFINED, 1, &jsonValue);
        JS_FreeValue(ctx, callResult);  // 🔥 반환값 해제
        JS_FreeValue(ctx, jsonValue);
        JS_FreeValue(ctx, resolvingFuncs[0]);
        JS_FreeValue(ctx, resolvingFuncs[1]);
        return promise;
    }

    static JSValue createMockFetchPromise(JSContext* ctx, const std::string& url, const std::string& method,
        const std::string& bodySnippet, bool sensitive) {
        JSValue resolvingFuncs[2];
        JSValue promise = JS_NewPromiseCapability(ctx, resolvingFuncs);
        if (JS_IsException(promise)) {
            JSValue exception = JS_GetException(ctx);
            JS_FreeValue(ctx, exception);
            return createMockFetchResponse(ctx, url, method, bodySnippet, sensitive);
        }

        JSValue response = createMockFetchResponse(ctx, url, method, bodySnippet, sensitive);
        JSValue callResult = JS_Call(ctx, resolvingFuncs[0], JS_UNDEFINED, 1, &response);
        JS_FreeValue(ctx, callResult);  // 🔥 반환값 해제
        JS_FreeValue(ctx, response);
        JS_FreeValue(ctx, resolvingFuncs[0]);
        JS_FreeValue(ctx, resolvingFuncs[1]);
        return promise;
    }

    // Proxy get handler
    static JSValue js_window_proxy_get(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 2) return JS_UNDEFINED;

        JSValue target = argv[0];
        JSValue prop = argv[1];

        const char* prop_cstr = JS_ToCString(ctx, prop);
        if (prop_cstr) {
            std::string prop_name = prop_cstr;
            JS_FreeCString(ctx, prop_cstr);

            if (prop_name == "fetch") {
                return JS_GetPropertyStr(ctx, target, "fetch");
            }
        }

        return JS_GetProperty(ctx, target, JS_ValueToAtom(ctx, prop));
    }

    void registerWindowObject(JSContext* ctx, JSValue global_obj) {
        // Navigator 등록
        JSValue navigator_obj = JS_NewObject(ctx);
        
        // userAgent
        JSCFunctionType nav_ua_getter_type;
        nav_ua_getter_type.getter = js_navigator_get_userAgent;
        JSValue nav_ua_getter = JS_NewCFunction2(ctx, nav_ua_getter_type.generic, "get_userAgent", 0, JS_CFUNC_getter, 0);
        JS_DefinePropertyGetSet(ctx, navigator_obj, JS_NewAtom(ctx, "userAgent"), nav_ua_getter, JS_UNDEFINED, JS_PROP_C_W_E);
        JS_FreeValue(ctx, nav_ua_getter);
        
        // 🔥 추가 navigator 속성들
        // platform
        JSCFunctionType nav_platform_getter_type;
        nav_platform_getter_type.getter = js_navigator_get_platform;
        JSValue nav_platform_getter = JS_NewCFunction2(ctx, nav_platform_getter_type.generic, "get_platform", 0, JS_CFUNC_getter, 0);
        JS_DefinePropertyGetSet(ctx, navigator_obj, JS_NewAtom(ctx, "platform"), nav_platform_getter, JS_UNDEFINED, JS_PROP_C_W_E);
        JS_FreeValue(ctx, nav_platform_getter);
        
        // vendor
        JSCFunctionType nav_vendor_getter_type;
        nav_vendor_getter_type.getter = js_navigator_get_vendor;
        JSValue nav_vendor_getter = JS_NewCFunction2(ctx, nav_vendor_getter_type.generic, "get_vendor", 0, JS_CFUNC_getter, 0);
        JS_DefinePropertyGetSet(ctx, navigator_obj, JS_NewAtom(ctx, "vendor"), nav_vendor_getter, JS_UNDEFINED, JS_PROP_C_W_E);
        JS_FreeValue(ctx, nav_vendor_getter);
        
        // language
        JSCFunctionType nav_language_getter_type;
        nav_language_getter_type.getter = js_navigator_get_language;
        JSValue nav_language_getter = JS_NewCFunction2(ctx, nav_language_getter_type.generic, "get_language", 0, JS_CFUNC_getter, 0);
        JS_DefinePropertyGetSet(ctx, navigator_obj, JS_NewAtom(ctx, "language"), nav_language_getter, JS_UNDEFINED, JS_PROP_C_W_E);
        JS_FreeValue(ctx, nav_language_getter);
        
        // hardwareConcurrency
        JSCFunctionType nav_hw_getter_type;
        nav_hw_getter_type.getter = js_navigator_get_hardwareConcurrency;
        JSValue nav_hw_getter = JS_NewCFunction2(ctx, nav_hw_getter_type.generic, "get_hardwareConcurrency", 0, JS_CFUNC_getter, 0);
        JS_DefinePropertyGetSet(ctx, navigator_obj, JS_NewAtom(ctx, "hardwareConcurrency"), nav_hw_getter, JS_UNDEFINED, JS_PROP_C_W_E);
        JS_FreeValue(ctx, nav_hw_getter);
        
        // deviceMemory
        JSCFunctionType nav_mem_getter_type;
        nav_mem_getter_type.getter = js_navigator_get_deviceMemory;
        JSValue nav_mem_getter = JS_NewCFunction2(ctx, nav_mem_getter_type.generic, "get_deviceMemory", 0, JS_CFUNC_getter, 0);
        JS_DefinePropertyGetSet(ctx, navigator_obj, JS_NewAtom(ctx, "deviceMemory"), nav_mem_getter, JS_UNDEFINED, JS_PROP_C_W_E);
        JS_FreeValue(ctx, nav_mem_getter);
        
        // maxTouchPoints
        JSCFunctionType nav_touch_getter_type;
        nav_touch_getter_type.getter = js_navigator_get_maxTouchPoints;
        JSValue nav_touch_getter = JS_NewCFunction2(ctx, nav_touch_getter_type.generic, "get_maxTouchPoints", 0, JS_CFUNC_getter, 0);
        JS_DefinePropertyGetSet(ctx, navigator_obj, JS_NewAtom(ctx, "maxTouchPoints"), nav_touch_getter, JS_UNDEFINED, JS_PROP_C_W_E);
        JS_FreeValue(ctx, nav_touch_getter);
        
        // Clipboard API 추가
        JSValue clipboard_obj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, clipboard_obj, "writeText", 
            JS_NewCFunction(ctx, js_navigator_clipboard_writeText, "writeText", 1));
        JS_SetPropertyStr(ctx, clipboard_obj, "write", 
            JS_NewCFunction(ctx, js_navigator_clipboard_write, "write", 1));
        JS_SetPropertyStr(ctx, navigator_obj, "clipboard", clipboard_obj);

        JS_SetPropertyStr(ctx, global_obj, "navigator", JS_DupValue(ctx, navigator_obj));

        // Window 객체
        JSValue window_obj = JS_NewObject(ctx);
        JSValue location_obj = JS_NewObject(ctx);

        JSCFunctionType setter_func_type;
        setter_func_type.setter = js_window_location_set_href;
        JSValue setter_obj = JS_NewCFunction2(ctx, setter_func_type.generic, "set_href", 1, JS_CFUNC_setter, 0);
        JS_DefinePropertyGetSet(ctx, location_obj, JS_NewAtom(ctx, "href"), JS_UNDEFINED, setter_obj, JS_PROP_C_W_E);
        JS_FreeValue(ctx, setter_obj);

        JS_SetPropertyStr(ctx, location_obj, "replace",
            JS_NewCFunction(ctx, js_window_location_replace, "replace", 1));
        JS_SetPropertyStr(ctx, location_obj, "assign",
            JS_NewCFunction(ctx, js_window_location_assign, "assign", 1));
        JS_SetPropertyStr(ctx, window_obj, "location", location_obj);
        JS_SetPropertyStr(ctx, window_obj, "fetch", JS_NewCFunction(ctx, js_fetch, "fetch", 2));

        JS_SetPropertyStr(ctx, window_obj, "navigator", JS_DupValue(ctx, navigator_obj));
        JS_FreeValue(ctx, navigator_obj);

        // 🔥 Screen 객체 등록
        JSValue screen_obj = JS_NewObject(ctx);
        
        // width
        JSCFunctionType screen_width_getter_type;
        screen_width_getter_type.getter = js_screen_get_width;
        JSValue screen_width_getter = JS_NewCFunction2(ctx, screen_width_getter_type.generic, "get_width", 0, JS_CFUNC_getter, 0);
        JS_DefinePropertyGetSet(ctx, screen_obj, JS_NewAtom(ctx, "width"), screen_width_getter, JS_UNDEFINED, JS_PROP_C_W_E);
        JS_FreeValue(ctx, screen_width_getter);
        
        // height
        JSCFunctionType screen_height_getter_type;
        screen_height_getter_type.getter = js_screen_get_height;
        JSValue screen_height_getter = JS_NewCFunction2(ctx, screen_height_getter_type.generic, "get_height", 0, JS_CFUNC_getter, 0);
        JS_DefinePropertyGetSet(ctx, screen_obj, JS_NewAtom(ctx, "height"), screen_height_getter, JS_UNDEFINED, JS_PROP_C_W_E);
        JS_FreeValue(ctx, screen_height_getter);
        
        // availWidth
        JSCFunctionType screen_availWidth_getter_type;
        screen_availWidth_getter_type.getter = js_screen_get_availWidth;
        JSValue screen_availWidth_getter = JS_NewCFunction2(ctx, screen_availWidth_getter_type.generic, "get_availWidth", 0, JS_CFUNC_getter, 0);
        JS_DefinePropertyGetSet(ctx, screen_obj, JS_NewAtom(ctx, "availWidth"), screen_availWidth_getter, JS_UNDEFINED, JS_PROP_C_W_E);
        JS_FreeValue(ctx, screen_availWidth_getter);
        
        // availHeight
        JSCFunctionType screen_availHeight_getter_type;
        screen_availHeight_getter_type.getter = js_screen_get_availHeight;
        JSValue screen_availHeight_getter = JS_NewCFunction2(ctx, screen_availHeight_getter_type.generic, "get_availHeight", 0, JS_CFUNC_getter, 0);
        JS_DefinePropertyGetSet(ctx, screen_obj, JS_NewAtom(ctx, "availHeight"), screen_availHeight_getter, JS_UNDEFINED, JS_PROP_C_W_E);
        JS_FreeValue(ctx, screen_availHeight_getter);
        
        // colorDepth
        JSCFunctionType screen_colorDepth_getter_type;
        screen_colorDepth_getter_type.getter = js_screen_get_colorDepth;
        JSValue screen_colorDepth_getter = JS_NewCFunction2(ctx, screen_colorDepth_getter_type.generic, "get_colorDepth", 0, JS_CFUNC_getter, 0);
        JS_DefinePropertyGetSet(ctx, screen_obj, JS_NewAtom(ctx, "colorDepth"), screen_colorDepth_getter, JS_UNDEFINED, JS_PROP_C_W_E);
        JS_FreeValue(ctx, screen_colorDepth_getter);
        
        // pixelDepth
        JSCFunctionType screen_pixelDepth_getter_type;
        screen_pixelDepth_getter_type.getter = js_screen_get_pixelDepth;
        JSValue screen_pixelDepth_getter = JS_NewCFunction2(ctx, screen_pixelDepth_getter_type.generic, "get_pixelDepth", 0, JS_CFUNC_getter, 0);
        JS_DefinePropertyGetSet(ctx, screen_obj, JS_NewAtom(ctx, "pixelDepth"), screen_pixelDepth_getter, JS_UNDEFINED, JS_PROP_C_W_E);
        JS_FreeValue(ctx, screen_pixelDepth_getter);
        
        // screen 객체를 window와 전역에 등록
        JS_SetPropertyStr(ctx, window_obj, "screen", JS_DupValue(ctx, screen_obj));
        JS_SetPropertyStr(ctx, global_obj, "screen", screen_obj);

        // Window 크기 속성 등록
        JSCFunctionType innerWidth_getter_type;
        innerWidth_getter_type.getter = js_window_get_innerWidth;
        JSValue innerWidth_getter = JS_NewCFunction2(ctx, innerWidth_getter_type.generic, "get_innerWidth", 0, JS_CFUNC_getter, 0);
        JS_DefinePropertyGetSet(ctx, window_obj, JS_NewAtom(ctx, "innerWidth"), innerWidth_getter, JS_UNDEFINED, JS_PROP_C_W_E);
        JS_FreeValue(ctx, innerWidth_getter);

        JSCFunctionType innerHeight_getter_type;
        innerHeight_getter_type.getter = js_window_get_innerHeight;
        JSValue innerHeight_getter = JS_NewCFunction2(ctx, innerHeight_getter_type.generic, "get_innerHeight", 0, JS_CFUNC_getter, 0);
        JS_DefinePropertyGetSet(ctx, window_obj, JS_NewAtom(ctx, "innerHeight"), innerHeight_getter, JS_UNDEFINED, JS_PROP_C_W_E);
        JS_FreeValue(ctx, innerHeight_getter);

        JS_SetPropertyStr(ctx, window_obj, "stop",
            JS_NewCFunction(ctx, js_window_stop, "stop", 0));
        
        // 🔥 NEW: window.open 추가
        JS_SetPropertyStr(ctx, window_obj, "open",
            JS_NewCFunction(ctx, js_window_open, "open", 3));

        // 🔥 addEventListener 추가 (window와 전역 모두)
        JS_SetPropertyStr(ctx, window_obj, "addEventListener",
            JS_NewCFunction(ctx, js_addEventListener, "addEventListener", 2));

        JSValue handler = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, handler, "get", JS_NewCFunction(ctx, js_window_proxy_get, "get", 2));

        JSValue proxy_ctor = JS_GetPropertyStr(ctx, global_obj, "Proxy");
        JSValue proxy_args[2] = { window_obj, handler };
        JSValue window_proxy = JS_CallConstructor(ctx, proxy_ctor, 2, proxy_args);
        JS_FreeValue(ctx, proxy_ctor);
        JS_FreeValue(ctx, handler);

        // 🔥 CRITICAL FIX: window.document 추가
        JSValue document_obj = JS_GetPropertyStr(ctx, global_obj, "document");
        JS_SetPropertyStr(ctx, window_obj, "document", JS_DupValue(ctx, document_obj));
        JS_FreeValue(ctx, document_obj);

        JS_SetPropertyStr(ctx, global_obj, "window", window_proxy);
        JS_SetPropertyStr(ctx, global_obj, "self", JS_DupValue(ctx, window_proxy));
        JS_SetPropertyStr(ctx, global_obj, "fetch", JS_NewCFunction(ctx, js_fetch, "fetch", 2));
    }

    // window.stop() - 페이지 로딩 중지 후킹
    JSValue js_window_stop(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::DOM_MANIPULATION,
                "window.stop",
                {},
                JsValue(std::monostate()),
                {{"action", JsValue("stop_page_loading")}},
                8
                });
        }

        return JS_UNDEFINED;
    }
    
    // Clipboard API 함수들
    JSValue js_navigator_clipboard_writeText(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        
        if (argc > 0) {
            const char* text_cstr = JS_ToCString(ctx, argv[0]);
            if (text_cstr) {
                std::string text = text_cstr;
                
                if (a_ctx) {
                    // DynamicAnalyzer에 이벤트 기록
                    if (a_ctx->dynamicAnalyzer) {
                        a_ctx->dynamicAnalyzer->recordEvent({
                            HookType::DATA_EXFILTRATION,
                            "navigator.clipboard.writeText",
                            {JsValue(text)},
                            JsValue(std::monostate()),
                            {},
                            10  // CRITICAL severity
                        });
                    }
                    
                    // DynamicStringTracker에 문자열 추적
                    if (a_ctx->dynamicStringTracker) {
                        a_ctx->dynamicStringTracker->trackString("clipboard_content", text);
                    }
                    
                    // ChainTrackerManager에 함수 호출 추적
                    if (a_ctx->chainTrackerManager) {
                        a_ctx->chainTrackerManager->trackFunctionCall(
                            "navigator.clipboard.writeText",
                            {JsValue(text)},
                            JsValue(std::monostate())
                        );
                    }
                }
                
                JS_FreeCString(ctx, text_cstr);
            }
        }
        
        // Promise를 반환 (실제로는 resolve된 Promise)
        return JS_NewObject(ctx);
    }
    
    JSValue js_navigator_clipboard_write(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        
        if (argc > 0) {
            // ClipboardItem 배열 처리 (간단히 문자열로 변환)
            std::string content = JSValueConverter::toString(ctx, argv[0]);
            
            if (a_ctx) {
                if (a_ctx->dynamicAnalyzer) {
                    a_ctx->dynamicAnalyzer->recordEvent({
                        HookType::DATA_EXFILTRATION,
                        "navigator.clipboard.write",
                        {JsValue(content)},
                        JsValue(std::monostate()),
                        {},
                        10
                    });
                }
                
                if (a_ctx->dynamicStringTracker) {
                    a_ctx->dynamicStringTracker->trackString("clipboard_content", content);
                }
            }
        }
        
        return JS_NewObject(ctx);
    }
    
    // 🔥 NEW: window.open 후킹
    JSValue js_window_open(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        
        if (argc > 0 && a_ctx) {
            const char* url_cstr = JS_ToCString(ctx, argv[0]);
            if (url_cstr) {
                std::string url = url_cstr;
                
                // URL 수집
                if (a_ctx->urlCollector) {
                    a_ctx->urlCollector->addUrlWithMetadata(url, "window.open", 0);
                }
                
                // 동적 분석 이벤트 기록
                if (a_ctx->dynamicAnalyzer) {
                    a_ctx->dynamicAnalyzer->recordEvent({
                        HookType::LOCATION_CHANGE,
                        "window.open",
                        {JsValue(url)},
                        JsValue(std::monostate()),
                        {},
                        7  // MEDIUM severity
                    });
                }
                
                // 체인 추적
                if (a_ctx->chainTrackerManager) {
                    a_ctx->chainTrackerManager->trackFunctionCall(
                        "window.open",
                        {JsValue(url)},
                        JsValue(std::monostate())
                    );
                }
                
                JS_FreeCString(ctx, url_cstr);
            }
        }
        
        // Mock window 객체 반환
        return JS_NewObject(ctx);
    }
}
