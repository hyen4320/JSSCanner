#pragma once
#include <string>
#include <map>

/**
 * 브라우저 환경 설정 관리
 * 악성코드의 환경 기반 우회(environment-based evasion) 탐지를 위한 설정
 */
class BrowserConfig {
public:
    // ==================== Navigator 설정 ====================
    std::string userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    std::string appVersion = "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    std::string appName = "Netscape";
    std::string appCodeName = "Mozilla";
    std::string platform = "Win32";
    std::string vendor = "Google Inc.";
    std::string vendorSub = "";
    std::string product = "Gecko";
    std::string productSub = "20030107";
    std::string language = "en-US";
    std::string languages = "en-US,en,ko";
    bool cookieEnabled = true;
    bool doNotTrack = false;
    int maxTouchPoints = 0;
    int hardwareConcurrency = 8;
    long long deviceMemory = 8;  // GB
    bool onLine = true;
    bool javaEnabled = false;
    bool pdfViewerEnabled = true;
    std::string oscpu = "";  // Firefox only
    std::string buildID = "";  // Firefox only
    
    // ==================== Screen 설정 ====================
    int screenWidth = 1920;
    int screenHeight = 1080;
    int screenAvailWidth = 1920;
    int screenAvailHeight = 1040;
    int screenColorDepth = 24;
    int screenPixelDepth = 24;
    std::string screenOrientation = "landscape-primary";  // portrait-primary, landscape-primary, etc.
    double devicePixelRatio = 1.0;
    
    // ==================== Window 설정 ====================
    int innerWidth = 1920;
    int innerHeight = 1080;
    int outerWidth = 1920;
    int outerHeight = 1080;
    int screenX = 0;
    int screenY = 0;
    int pageXOffset = 0;
    int pageYOffset = 0;
    int scrollX = 0;
    int scrollY = 0;
    std::string name = "";  // window.name
    bool closed = false;
    
    // ==================== WebGL & Canvas 설정 ====================
    std::string webglVendor = "Google Inc. (NVIDIA)";
    std::string webglRenderer = "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0)";
    std::string webglVersion = "WebGL 1.0 (OpenGL ES 2.0 Chromium)";
    std::string webglShadingLanguageVersion = "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)";
    int webglMaxTextureSize = 16384;
    int webglMaxViewportDims = 16384;
    
    // ==================== Plugins 설정 ====================
    int pluginsLength = 5;  // navigator.plugins.length
    std::string pluginsList = "Chrome PDF Plugin,Chrome PDF Viewer,Native Client";  // 플러그인 목록
    
    // ==================== Battery API ====================
    bool batteryCharging = true;
    double batteryLevel = 1.0;  // 0.0 ~ 1.0
    int batteryChargingTime = 0;  // seconds, 0 = fully charged
    int batteryDischargingTime = INT_MAX;  // seconds, Infinity when charging
    
    // ==================== Connection API ====================
    std::string connectionType = "wifi";  // wifi, cellular, ethernet, none, unknown
    std::string connectionEffectiveType = "4g";  // slow-2g, 2g, 3g, 4g
    double connectionDownlink = 10.0;  // Mbps
    double connectionRtt = 50.0;  // ms
    bool connectionSaveData = false;
    
    // ==================== Document 설정 ====================
    std::string documentDomain = "example.com";
    std::string documentReferrer = "";
    std::string documentTitle = "Example Page";
    std::string documentURL = "https://example.com/page.html";
    std::string documentCookie = "";
    std::string documentCharacterSet = "UTF-8";
    std::string documentReadyState = "complete";  // loading, interactive, complete
    bool documentHidden = false;
    std::string documentVisibilityState = "visible";  // visible, hidden, prerender
    
    // ==================== Permissions API ====================
    bool permissionNotifications = false;
    bool permissionGeolocation = false;
    bool permissionCamera = false;
    bool permissionMicrophone = false;
    bool permissionPersistentStorage = false;
    
    // ==================== Media Devices ====================
    int mediaDevicesVideoInputCount = 1;  // 웹캠 수
    int mediaDevicesAudioInputCount = 1;  // 마이크 수
    int mediaDevicesAudioOutputCount = 1;  // 스피커 수
    
    // ==================== Timezone & Locale ====================
    int timezoneOffset = -540;  // minutes from UTC (예: KST = UTC+9 = -540)
    std::string timezoneName = "Asia/Seoul";
    std::string dateTimeFormat = "ko-KR";
    std::string numberFormat = "ko-KR";
    
    // ==================== Performance & Timing ====================
    long long performanceTimingNavigationStart = 1700000000000;  // milliseconds since epoch
    long long performanceTimingLoadEventEnd = 1700000001500;
    long long performanceMemoryUsedJSHeapSize = 10000000;  // bytes
    long long performanceMemoryTotalJSHeapSize = 20000000;
    long long performanceMemoryJSHeapSizeLimit = 2172649472;
    
    // ==================== Chrome-specific (automation detection) ====================
    bool hasChrome = true;  // window.chrome 존재 여부
    bool hasChromeRuntime = true;  // chrome.runtime 존재 여부
    bool hasWebdriver = false;  // navigator.webdriver (Selenium 탐지)
    std::string chromeLoadTimes = "";  // chrome.loadTimes() 결과
    
    // ==================== Canvas & Audio Fingerprinting ====================
    std::string canvasFingerprint = "";  // Canvas fingerprint hash (비어있으면 자동 생성)
    std::string audioFingerprint = "";  // Audio context fingerprint
    
    // ==================== WebRTC ====================
    bool webrtcEnabled = true;
    std::string webrtcLocalIP = "192.168.1.100";
    std::string webrtcPublicIP = "203.0.113.1";
    
    // ==================== 미리 정의된 프로필 ====================
    static BrowserConfig getDefaultDesktopProfile();
    static BrowserConfig getMobileProfile();
    static BrowserConfig getHeadlessProfile();  // 헤드리스 브라우저 프로필
    static BrowserConfig getSandboxProfile();   // 샌드박스 환경 프로필
    
    // JSON으로부터 설정 로드
    static BrowserConfig loadFromJson(const std::string& jsonPath);
    
    // 설정을 JSON 문자열로 변환
    std::string toJson() const;
    
    // ==================== JavaScript 환경 초기화 ====================
    // QuickJS Context에 브라우저 환경(navigator, document, location 등)을 설정
    void initializeJSEnvironment(void* jsContext) const;  // JSContext* ctx
};
