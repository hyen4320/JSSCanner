#include "pch.h"
#include "BrowserConfig.h"
#include "../quickjs.h"
#include <fstream>
#include <cstring>

// ==================== 미리 정의된 프로필 ====================

BrowserConfig BrowserConfig::getDefaultDesktopProfile() {
    BrowserConfig config;

    // Navigator
    config.userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    config.appVersion = "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    config.appName = "Netscape";
    config.platform = "Win32";
    config.vendor = "Google Inc.";
    config.product = "Gecko";
    config.language = "en-US";
    config.languages = "en-US,en";
    config.cookieEnabled = true;
    config.doNotTrack = false;
    config.maxTouchPoints = 0;
    config.hardwareConcurrency = 8;
    config.deviceMemory = 8;
    config.onLine = true;
    config.javaEnabled = false;
    config.pdfViewerEnabled = true;

    // Screen
    config.screenWidth = 1920;
    config.screenHeight = 1080;
    config.screenAvailWidth = 1920;
    config.screenAvailHeight = 1040;
    config.screenColorDepth = 24;
    config.screenPixelDepth = 24;
    config.screenOrientation = "landscape-primary";
    config.devicePixelRatio = 1.0;

    // Window
    config.innerWidth = 1920;
    config.innerHeight = 1080;
    config.outerWidth = 1920;
    config.outerHeight = 1080;
    config.screenX = 0;
    config.screenY = 0;
    config.closed = false;

    // WebGL
    config.webglVendor = "Google Inc. (NVIDIA)";
    config.webglRenderer = "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080)";
    config.webglVersion = "WebGL 1.0";
    config.webglMaxTextureSize = 16384;

    // Plugins
    config.pluginsLength = 5;
    config.pluginsList = "Chrome PDF Plugin,Chrome PDF Viewer,Native Client";

    // Battery
    config.batteryCharging = true;
    config.batteryLevel = 1.0;

    return config;
}

// ==================== JavaScript 환경 초기화 ====================

void BrowserConfig::initializeJSEnvironment(void* jsContext) const {
    JSContext* ctx = static_cast<JSContext*>(jsContext);
    if (!ctx) return;
    
    JSValue global = JS_GetGlobalObject(ctx);
    
    // ============================================
    // Navigator 객체 생성 및 바인딩
    // ============================================
    JSValue navigator = JS_NewObject(ctx);
    
    // userAgent
    JS_DefinePropertyValueStr(ctx, navigator, "userAgent",
        JS_NewString(ctx, userAgent.c_str()), JS_PROP_C_W_E);
    
    // platform
    JS_DefinePropertyValueStr(ctx, navigator, "platform",
        JS_NewString(ctx, platform.c_str()), JS_PROP_C_W_E);
    
    // appName
    JS_DefinePropertyValueStr(ctx, navigator, "appName",
        JS_NewString(ctx, appName.c_str()), JS_PROP_C_W_E);
    
    // appVersion
    JS_DefinePropertyValueStr(ctx, navigator, "appVersion",
        JS_NewString(ctx, appVersion.c_str()), JS_PROP_C_W_E);
    
    // vendor
    JS_DefinePropertyValueStr(ctx, navigator, "vendor",
        JS_NewString(ctx, vendor.c_str()), JS_PROP_C_W_E);
    
    // language
    JS_DefinePropertyValueStr(ctx, navigator, "language",
        JS_NewString(ctx, language.c_str()), JS_PROP_C_W_E);
    
    // languages 배열 생성
    JSValue languagesArray = JS_NewArray(ctx);
    size_t idx = 0;
    std::string langStr = languages;
    size_t pos = 0;
    while ((pos = langStr.find(',')) != std::string::npos) {
        std::string lang = langStr.substr(0, pos);
        JS_SetPropertyUint32(ctx, languagesArray, idx++, JS_NewString(ctx, lang.c_str()));
        langStr.erase(0, pos + 1);
    }
    if (!langStr.empty()) {
        JS_SetPropertyUint32(ctx, languagesArray, idx, JS_NewString(ctx, langStr.c_str()));
    }
    JS_DefinePropertyValueStr(ctx, navigator, "languages", languagesArray, JS_PROP_C_W_E);
    
    // onLine
    JS_DefinePropertyValueStr(ctx, navigator, "onLine",
        JS_NewBool(ctx, onLine ? 1 : 0), JS_PROP_C_W_E);
    
    // cookieEnabled
    JS_DefinePropertyValueStr(ctx, navigator, "cookieEnabled",
        JS_NewBool(ctx, cookieEnabled ? 1 : 0), JS_PROP_C_W_E);
    
    // hardwareConcurrency
    JS_DefinePropertyValueStr(ctx, navigator, "hardwareConcurrency",
        JS_NewInt32(ctx, hardwareConcurrency), JS_PROP_C_W_E);
    
    // deviceMemory
    JS_DefinePropertyValueStr(ctx, navigator, "deviceMemory",
        JS_NewInt64(ctx, deviceMemory), JS_PROP_C_W_E);
    
    // maxTouchPoints
    JS_DefinePropertyValueStr(ctx, navigator, "maxTouchPoints",
        JS_NewInt32(ctx, maxTouchPoints), JS_PROP_C_W_E);
    
    // webdriver
    JS_DefinePropertyValueStr(ctx, navigator, "webdriver",
        JS_NewBool(ctx, hasWebdriver ? 1 : 0), JS_PROP_C_W_E);
    
    // Global에 navigator 등록
    JS_DefinePropertyValueStr(ctx, global, "navigator", navigator, JS_PROP_C_W_E);
    
    // ============================================
    // Location 객체 생성
    // ============================================
    JSValue location = JS_NewObject(ctx);
    JS_DefinePropertyValueStr(ctx, location, "href",
        JS_NewString(ctx, documentURL.c_str()), JS_PROP_C_W_E);
    
    // URL 파싱 (간단한 구현)
    std::string protocol = "about:";
    std::string host = "";
    std::string hostname = "";
    std::string pathname = "blank";
    
    if (documentURL.find("://") != std::string::npos) {
        size_t protocolEnd = documentURL.find("://");
        protocol = documentURL.substr(0, protocolEnd + 1);  // "https:"
        
        size_t hostStart = protocolEnd + 3;
        size_t pathStart = documentURL.find('/', hostStart);
        
        if (pathStart != std::string::npos) {
            host = documentURL.substr(hostStart, pathStart - hostStart);
            hostname = host;
            pathname = documentURL.substr(pathStart);
        } else {
            host = documentURL.substr(hostStart);
            hostname = host;
            pathname = "/";
        }
    }
    
    JS_DefinePropertyValueStr(ctx, location, "protocol",
        JS_NewString(ctx, protocol.c_str()), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, location, "host",
        JS_NewString(ctx, host.c_str()), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, location, "hostname",
        JS_NewString(ctx, hostname.c_str()), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, location, "pathname",
        JS_NewString(ctx, pathname.c_str()), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, location, "search",
        JS_NewString(ctx, ""), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, location, "hash",
        JS_NewString(ctx, ""), JS_PROP_C_W_E);
    
    // ============================================
    // Document 객체 확인 및 설정
    // ============================================
    JSValue document = JS_GetPropertyStr(ctx, global, "document");
    if (JS_IsUndefined(document) || JS_IsNull(document)) {
        document = JS_NewObject(ctx);
        
        // readyState
        JS_DefinePropertyValueStr(ctx, document, "readyState",
            JS_NewString(ctx, documentReadyState.c_str()), JS_PROP_C_W_E);
        
        // createElement 더미 함수
        const char* createElementCode = "(function(tag) { return {}; })";
        JSValue createElement = JS_Eval(ctx, createElementCode, 
                                        strlen(createElementCode),
                                        "<createElement>", 
                                        JS_EVAL_TYPE_GLOBAL);
        JS_DefinePropertyValueStr(ctx, document, "createElement",
            createElement, JS_PROP_C_W_E);
        
        JS_DefinePropertyValueStr(ctx, global, "document", document, JS_PROP_C_W_E);
    }
    
    // document.location 설정
    JS_DefinePropertyValueStr(ctx, document, "location",
        JS_DupValue(ctx, location), JS_PROP_C_W_E);
    
    // window.location도 동일하게 설정
    JS_DefinePropertyValueStr(ctx, global, "location", location, JS_PROP_C_W_E);
    
    // ============================================
    // Screen 객체 생성
    // ============================================
    JSValue screen = JS_NewObject(ctx);
    JS_DefinePropertyValueStr(ctx, screen, "width",
        JS_NewInt32(ctx, screenWidth), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, screen, "height",
        JS_NewInt32(ctx, screenHeight), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, screen, "availWidth",
        JS_NewInt32(ctx, screenAvailWidth), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, screen, "availHeight",
        JS_NewInt32(ctx, screenAvailHeight), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, screen, "colorDepth",
        JS_NewInt32(ctx, screenColorDepth), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(ctx, screen, "pixelDepth",
        JS_NewInt32(ctx, screenPixelDepth), JS_PROP_C_W_E);
    
    JS_DefinePropertyValueStr(ctx, global, "screen", screen, JS_PROP_C_W_E);
    
    // Cleanup
    JS_FreeValue(ctx, document);
    JS_FreeValue(ctx, global);
}