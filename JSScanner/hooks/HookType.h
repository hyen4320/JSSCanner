#pragma once
#include <string>
#include <utility>

// ========================================
// HookType: 후킹 이벤트 타입 & Feature 키 & Detection 이름 통합
// ========================================
enum class HookType {
    // ==================== 후킹 이벤트 타입 (Detection 이름으로 사용) ====================
    FUNCTION_CALL,              // 함수 호출 (eval, Function 등) - Severity: 10 (eval)
    FETCH_REQUEST,              // fetch/XMLHttpRequest 네트워크 요청 - Severity: 0-9
    DOM_MANIPULATION,           // DOM 조작 (document.write, innerHTML 등) - Severity: 4-9
    LOCATION_CHANGE,            // 페이지 리다이렉션 (window.location 등) - Severity: 7
    CRYPTO_OPERATION,           // 암호화/복호화 작업 (atob, btoa 등) - Severity: 7
    DATA_EXFILTRATION,          // 데이터 유출 시도 - Severity: 8-10
    ADDR_MANIPULATION,          // 주소창 조작/스푸핑 - Severity: 8
    ENVIRONMENT_DETECTION,      // 환경 감지 (User-Agent, screen size 등) - Severity: 6
    ACTIVEX_OBJECT_CREATION,    // ActiveXObject 생성 - Severity: 9
    ACTIVEX_METHOD_CALL,        // ActiveXObject 메서드 호출 - Severity: 9

    // High Priority APIs
    WEBSOCKET_CONNECT,          // WebSocket 연결 생성 - Severity: 8-10 (ws:// 10, suspicious 9, normal 8)
    WEBSOCKET_SEND,             // WebSocket 메시지 전송 - Severity: 7-10 (sensitive 10, command 9, base64 8, normal 7)
    WEBSOCKET_MESSAGE,          // WebSocket 메시지 수신 - Severity: 9-10 (eval/Function 10, normal 9)
    WORKER_CREATE,              // Worker 생성 - Severity: 8-9 (blob/data URL 9, normal 8)
    WORKER_POST_MESSAGE,        // Worker 메시지 전송 - Severity: 7-10 (sensitive 10, normal 7)
    SHARED_WORKER_CREATE,       // SharedWorker 생성 - Severity: 8-9 (blob/data URL 9, normal 8)
    INDEXEDDB_OPEN,             // IndexedDB 열기 - Severity: 7
    INDEXEDDB_TRANSACTION,      // IndexedDB 트랜잭션 - Severity: 7
    INDEXEDDB_ADD,              // IndexedDB 데이터 추가 - Severity: 7-9 (sensitive 9, normal 7)
    BLOB_CREATE,                // Blob 생성 - Severity: 8-9 (executable 9, normal 8)
    FILE_CREATE,                // File 생성 - Severity: 8
    URL_CREATE_OBJECT_URL,      // URL.createObjectURL - Severity: 8-10 (executable 10, suspicious 9, normal 8)
    CRYPTO_ENCRYPT,             // crypto.subtle.encrypt - Severity: 7
    CRYPTO_DECRYPT,             // crypto.subtle.decrypt - Severity: 7
    CRYPTO_IMPORT_KEY,          // crypto.subtle.importKey - Severity: 7

    // Medium Priority APIs
    NAVIGATOR_SEND_BEACON,      // navigator.sendBeacon - Severity: 6-10 (sensitive 10, normal 6)
    SHADOW_DOM_ATTACH,          // Element.attachShadow - Severity: 8
    WASM_INSTANTIATE,           // WebAssembly.instantiate - Severity: 8-9 (base64 9, normal 8)
    WASM_COMPILE,               // WebAssembly.compile - Severity: 8
    MUTATION_OBSERVER_CREATE,   // MutationObserver 생성 - Severity: 7
    MUTATION_OBSERVER_OBSERVE,  // MutationObserver.observe - Severity: 7
    SESSION_STORAGE_SET,        // sessionStorage.setItem - Severity: 6-9 (sensitive 9, normal 6)
    SESSION_STORAGE_GET,        // sessionStorage.getItem - Severity: 5

    // Low Priority APIs
    NOTIFICATION_CREATE,        // new Notification - Severity: 6-8 (suspicious 8, normal 6)
    NOTIFICATION_PERMISSION,    // Notification.requestPermission - Severity: 6
    GEOLOCATION_GET,            // navigator.geolocation.getCurrentPosition - Severity: 8
    GEOLOCATION_WATCH,          // navigator.geolocation.watchPosition - Severity: 8
    CLIPBOARD_WRITE,            // navigator.clipboard.writeText - Severity: 7-9 (sensitive 9, normal 7)
    CLIPBOARD_READ,             // navigator.clipboard.readText - Severity: 8
    WEBRTC_CREATE,              // new RTCPeerConnection - Severity: 7
    WEBRTC_DATA_CHANNEL,        // createDataChannel - Severity: 7
    RAF_CREATE,                 // requestAnimationFrame - Severity: 5
    CONSOLE_LOG,                // console.log - Severity: 3
    CONSOLE_WARN,               // console.warn - Severity: 3
    CONSOLE_ERROR,              // console.error - Severity: 3

    // ==================== Detection 이름 (JSScanner.XXX - Static Analysis) ====================
    OBFUSCATION_CHAINS,         // JSScanner.OBFUSCATION_CHAINS - Severity: 7-10
    ATTACK_CHAIN,               // JSScanner.ATTACK_CHAIN - Severity: 7-10
    JAVASCRIPT_CODE_IN_VARIABLE, // JSScanner.JAVASCRIPT_CODE_IN_VARIABLE - Severity: 7
    HTML_CODE_IN_VARIABLE,      // JSScanner.HTML_CODE_IN_VARIABLE - Severity: 6
    MALICIOUS_PATTERN,          // JSScanner.MALICIOUS_PATTERN - Severity: 9
    MALICIOUS_PATTERN_BLOCKED,  // JSScanner.MALICIOUS_PATTERN_BLOCKED - Severity: 10
    DECODING_CHAIN,             // JSScanner.DECODING_CHAIN - Severity: 8
    OBFUSCATED_VARIABLES,       // JSScanner.OBFUSCATED_VARIABLES - Severity: 7
    ARRAY_OBFUSCATION,          // JSScanner.ARRAY_OBFUSCATION - Severity: 7
    LARGE_ENCODED_DATA,         // JSScanner.LARGE_ENCODED_DATA - Severity: 8
    ANTI_ANALYSIS,              // JSScanner.ANTI_ANALYSIS - Severity: 9
    IIFE_OBFUSCATION,           // JSScanner.IIFE_OBFUSCATION - Severity: 6
    SUSPICIOUS_CODE,            // JSScanner.SUSPICIOUS_CODE - Severity: 3-7
    INDIRECT_PROPERTY_ACCESS,   // JSScanner.INDIRECT_PROPERTY_ACCESS - Severity: 10
    SUSPICIOUS_VARIABLE,        // JSScanner.SUSPICIOUS_VARIABLE - Severity: 7
    SUSPICIOUS_TRACKED_STRING,  // JSScanner.SUSPICIOUS_TRACKED_STRING - Severity: 6
    CLIPBOARD_API,              // JSScanner.CLIPBOARD_API - Severity: 7
    MALICIOUS_COMMAND,          // JSScanner.MALICIOUS_COMMAND - Severity: 9
    SCRIPT_INJECTION,           // JSScanner.SCRIPT_INJECTION - Severity: 9
    REMOTE_MALICIOUS_FILE,      // JSScanner.REMOTE_MALICIOUS_FILE - Severity: 10
    CLIPBOARD_HIJACKING,        // JSScanner.CLIPBOARD_HIJACKING - Severity: 10
    ACTIVEX_USAGE,              // JSScanner.ACTIVEX_USAGE - Severity: 9
    WSCRIPT_USAGE,              // JSScanner.WSCRIPT_USAGE - Severity: 9
    STATIC_FINDING,             // JSScanner.STATIC_FINDING (fallback) - Severity: 5

    // ==================== Feature 키 (Detection.features 맵용) ====================
    ATTACK_CHAINS,              // 공격 체인 전체 정보
    SUMMARY,                    // 요약 정보
    INDIRECT_ACCESS_SUMMARY,    // 간접 접근 요약
    INDIRECT_ACCESS_COUNT,      // 간접 접근 횟수
    INDIRECT_ACCESS_PREFIX,     // 간접 접근 개별 항목 (+ 번호)
    CRYPTO_OPERATION_PREFIX,    // 암호화 작업 개별 (+ 번호)
    FUNCTION_CALL_PREFIX,       // 함수 호출 개별 (+ 번호)
    STRING_TRACKING_COUNT,      // 문자열 추적 개수
    STRING_TRACKING_PREFIX,     // 문자열 추적 개별 (+ 번호)
    TOTAL_CHAINS,               // 전체 체인 수
    HIGHEST_SEVERITY,           // 최고 심각도
    EVENT_COUNT,                // 이벤트 개수
    EVAL_DETECTED,              // eval 탐지 여부
    REDIRECT_COUNT,             // 리다이렉트 개수
    REDIRECT_PREFIX,            // 리다이렉트 개별 (+ 번호)
    DETECTION_COUNT,            // 탐지 개수
    CHAIN_PREFIX,               // 체인 개별 (+ 번호)
    FETCH_REQUEST_SUMMARY,      // Fetch 요청 요약
    TAINT_PATTERNS_SUMMARY,     // Taint 패턴 요약
    DURATION_MS,                // 지속 시간 (밀리초)
    TIME_RANGE,                 // 시간 범위
    THREATS,                    // 위협 정보
    EXTERNAL_PREFIX,            // 외부 리소스 개별 (+ 번호)
    SCAN_TARGET,                // 스캔 대상 URL
    EXTERNAL_COUNT,             // 외부 리소스 개수
    CRITICAL_COUNT,             // 위험 요소 개수
    MANIPULATION_COUNT,         // 조작 개수
    MANIPULATION_PREFIX,        // 조작 개별 (+ 번호)
    PROPERTY_COUNT,             // 속성 개수
    DETECTED_PREFIX,            // 탐지 항목 개별 (+ 번호)
    CHAIN_COUNT                 // 체인 개수
};

// Helper function to convert HookType enum to string
inline std::string HookTypeToString(HookType type) {
    switch (type) {
    // 후킹 이벤트 타입
    case HookType::FUNCTION_CALL: return "FUNCTION_CALL";
    case HookType::FETCH_REQUEST: return "FETCH_REQUEST";
    case HookType::DOM_MANIPULATION: return "DOM_MANIPULATION";
    case HookType::LOCATION_CHANGE: return "LOCATION_CHANGE";
    case HookType::CRYPTO_OPERATION: return "CRYPTO_OPERATION";
    case HookType::DATA_EXFILTRATION: return "DATA_EXFILTRATION";
    case HookType::ADDR_MANIPULATION: return "ADDR_MANIPULATION";
    case HookType::ENVIRONMENT_DETECTION: return "ENVIRONMENT_DETECTION";
    case HookType::ACTIVEX_OBJECT_CREATION: return "ACTIVEX_OBJECT_CREATION";
    case HookType::ACTIVEX_METHOD_CALL: return "ACTIVEX_METHOD_CALL";

    // High Priority APIs
    case HookType::WEBSOCKET_CONNECT: return "WEBSOCKET_CONNECT";
    case HookType::WEBSOCKET_SEND: return "WEBSOCKET_SEND";
    case HookType::WEBSOCKET_MESSAGE: return "WEBSOCKET_MESSAGE";
    case HookType::WORKER_CREATE: return "WORKER_CREATE";
    case HookType::WORKER_POST_MESSAGE: return "WORKER_POST_MESSAGE";
    case HookType::SHARED_WORKER_CREATE: return "SHARED_WORKER_CREATE";
    case HookType::INDEXEDDB_OPEN: return "INDEXEDDB_OPEN";
    case HookType::INDEXEDDB_TRANSACTION: return "INDEXEDDB_TRANSACTION";
    case HookType::INDEXEDDB_ADD: return "INDEXEDDB_ADD";
    case HookType::BLOB_CREATE: return "BLOB_CREATE";
    case HookType::FILE_CREATE: return "FILE_CREATE";
    case HookType::URL_CREATE_OBJECT_URL: return "URL_CREATE_OBJECT_URL";
    case HookType::CRYPTO_ENCRYPT: return "CRYPTO_ENCRYPT";
    case HookType::CRYPTO_DECRYPT: return "CRYPTO_DECRYPT";
    case HookType::CRYPTO_IMPORT_KEY: return "CRYPTO_IMPORT_KEY";

    // Medium Priority APIs
    case HookType::NAVIGATOR_SEND_BEACON: return "NAVIGATOR_SEND_BEACON";
    case HookType::SHADOW_DOM_ATTACH: return "SHADOW_DOM_ATTACH";
    case HookType::WASM_INSTANTIATE: return "WASM_INSTANTIATE";
    case HookType::WASM_COMPILE: return "WASM_COMPILE";
    case HookType::MUTATION_OBSERVER_CREATE: return "MUTATION_OBSERVER_CREATE";
    case HookType::MUTATION_OBSERVER_OBSERVE: return "MUTATION_OBSERVER_OBSERVE";
    case HookType::SESSION_STORAGE_SET: return "SESSION_STORAGE_SET";
    case HookType::SESSION_STORAGE_GET: return "SESSION_STORAGE_GET";

    // Low Priority APIs
    case HookType::NOTIFICATION_CREATE: return "NOTIFICATION_CREATE";
    case HookType::NOTIFICATION_PERMISSION: return "NOTIFICATION_PERMISSION";
    case HookType::GEOLOCATION_GET: return "GEOLOCATION_GET";
    case HookType::GEOLOCATION_WATCH: return "GEOLOCATION_WATCH";
    case HookType::CLIPBOARD_WRITE: return "CLIPBOARD_WRITE";
    case HookType::CLIPBOARD_READ: return "CLIPBOARD_READ";
    case HookType::WEBRTC_CREATE: return "WEBRTC_CREATE";
    case HookType::WEBRTC_DATA_CHANNEL: return "WEBRTC_DATA_CHANNEL";
    case HookType::RAF_CREATE: return "RAF_CREATE";
    case HookType::CONSOLE_LOG: return "CONSOLE_LOG";
    case HookType::CONSOLE_WARN: return "CONSOLE_WARN";
    case HookType::CONSOLE_ERROR: return "CONSOLE_ERROR";

    // Detection 이름
    case HookType::OBFUSCATION_CHAINS: return "OBFUSCATION_CHAINS";
    case HookType::ATTACK_CHAIN: return "ATTACK_CHAIN";
    case HookType::JAVASCRIPT_CODE_IN_VARIABLE: return "JAVASCRIPT_CODE_IN_VARIABLE";
    case HookType::HTML_CODE_IN_VARIABLE: return "HTML_CODE_IN_VARIABLE";
    case HookType::MALICIOUS_PATTERN: return "MALICIOUS_PATTERN";
    case HookType::MALICIOUS_PATTERN_BLOCKED: return "MALICIOUS_PATTERN_BLOCKED";
    case HookType::DECODING_CHAIN: return "DECODING_CHAIN";
    case HookType::OBFUSCATED_VARIABLES: return "OBFUSCATED_VARIABLES";
    case HookType::ARRAY_OBFUSCATION: return "ARRAY_OBFUSCATION";
    case HookType::LARGE_ENCODED_DATA: return "LARGE_ENCODED_DATA";
    case HookType::ANTI_ANALYSIS: return "ANTI_ANALYSIS";
    case HookType::IIFE_OBFUSCATION: return "IIFE_OBFUSCATION";
    case HookType::SUSPICIOUS_CODE: return "SUSPICIOUS_CODE";
    case HookType::INDIRECT_PROPERTY_ACCESS: return "INDIRECT_PROPERTY_ACCESS";
    case HookType::SUSPICIOUS_VARIABLE: return "SUSPICIOUS_VARIABLE";
    case HookType::SUSPICIOUS_TRACKED_STRING: return "SUSPICIOUS_TRACKED_STRING";
    case HookType::CLIPBOARD_API: return "CLIPBOARD_API";
    case HookType::MALICIOUS_COMMAND: return "MALICIOUS_COMMAND";
    case HookType::SCRIPT_INJECTION: return "SCRIPT_INJECTION";
    case HookType::REMOTE_MALICIOUS_FILE: return "REMOTE_MALICIOUS_FILE";
    case HookType::CLIPBOARD_HIJACKING: return "CLIPBOARD_HIJACKING";
    case HookType::ACTIVEX_USAGE: return "ACTIVEX_USAGE";
    case HookType::WSCRIPT_USAGE: return "WSCRIPT_USAGE";
    case HookType::STATIC_FINDING: return "STATIC_FINDING";

    // Feature 키
    case HookType::ATTACK_CHAINS: return "ATTACK_CHAINS";
    case HookType::SUMMARY: return "SUMMARY";
    case HookType::INDIRECT_ACCESS_SUMMARY: return "INDIRECT_ACCESS_SUMMARY";
    case HookType::INDIRECT_ACCESS_COUNT: return "INDIRECT_ACCESS_COUNT";
    case HookType::INDIRECT_ACCESS_PREFIX: return "INDIRECT_ACCESS_";
    case HookType::CRYPTO_OPERATION_PREFIX: return "CRYPTO_OPERATION_";
    case HookType::FUNCTION_CALL_PREFIX: return "FUNCTION_CALL_";
    case HookType::STRING_TRACKING_COUNT: return "STRING_TRACKING_COUNT";
    case HookType::STRING_TRACKING_PREFIX: return "STRING_TRACKING_";
    case HookType::TOTAL_CHAINS: return "TOTAL_CHAINS";
    case HookType::HIGHEST_SEVERITY: return "HIGHEST_SEVERITY";
    case HookType::EVENT_COUNT: return "EVENT_COUNT";
    case HookType::EVAL_DETECTED: return "EVAL_DETECTED";
    case HookType::REDIRECT_COUNT: return "REDIRECT_COUNT";
    case HookType::REDIRECT_PREFIX: return "REDIRECT_";
    case HookType::DETECTION_COUNT: return "DETECTION_COUNT";
    case HookType::CHAIN_PREFIX: return "CHAIN_";
    case HookType::FETCH_REQUEST_SUMMARY: return "FETCH_REQUEST_SUMMARY";
    case HookType::TAINT_PATTERNS_SUMMARY: return "TAINT_PATTERNS_SUMMARY";
    case HookType::DURATION_MS: return "DURATION_MS";
    case HookType::TIME_RANGE: return "TIME_RANGE";
    case HookType::THREATS: return "THREATS";
    case HookType::EXTERNAL_PREFIX: return "EXTERNAL_";
    case HookType::SCAN_TARGET: return "SCAN_TARGET";
    case HookType::EXTERNAL_COUNT: return "EXTERNAL_COUNT";
    case HookType::CRITICAL_COUNT: return "CRITICAL_COUNT";
    case HookType::MANIPULATION_COUNT: return "MANIPULATION_COUNT";
    case HookType::MANIPULATION_PREFIX: return "MANIPULATION_";
    case HookType::PROPERTY_COUNT: return "PROPERTY_COUNT";
    case HookType::DETECTED_PREFIX: return "DETECTED_";
    case HookType::CHAIN_COUNT: return "CHAIN_COUNT";
    }
    return "UNKNOWN";
}

// Helper function to convert string to HookType enum
inline HookType StringToHookType(const std::string& str) {
    // 후킹 이벤트 타입
    if (str == "FUNCTION_CALL") return HookType::FUNCTION_CALL;
    if (str == "FETCH_REQUEST") return HookType::FETCH_REQUEST;
    if (str == "DOM_MANIPULATION") return HookType::DOM_MANIPULATION;
    if (str == "LOCATION_CHANGE") return HookType::LOCATION_CHANGE;
    if (str == "CRYPTO_OPERATION") return HookType::CRYPTO_OPERATION;
    if (str == "DATA_EXFILTRATION") return HookType::DATA_EXFILTRATION;
    if (str == "ADDR_MANIPULATION") return HookType::ADDR_MANIPULATION;
    if (str == "ENVIRONMENT_DETECTION") return HookType::ENVIRONMENT_DETECTION;
    if (str == "ACTIVEX_OBJECT_CREATION") return HookType::ACTIVEX_OBJECT_CREATION;
    if (str == "ACTIVEX_METHOD_CALL") return HookType::ACTIVEX_METHOD_CALL;

    // High Priority
    if (str == "WEBSOCKET_CONNECT") return HookType::WEBSOCKET_CONNECT;
    if (str == "WEBSOCKET_SEND") return HookType::WEBSOCKET_SEND;
    if (str == "WEBSOCKET_MESSAGE") return HookType::WEBSOCKET_MESSAGE;
    if (str == "WORKER_CREATE") return HookType::WORKER_CREATE;
    if (str == "WORKER_POST_MESSAGE") return HookType::WORKER_POST_MESSAGE;
    if (str == "SHARED_WORKER_CREATE") return HookType::SHARED_WORKER_CREATE;
    if (str == "INDEXEDDB_OPEN") return HookType::INDEXEDDB_OPEN;
    if (str == "INDEXEDDB_TRANSACTION") return HookType::INDEXEDDB_TRANSACTION;
    if (str == "INDEXEDDB_ADD") return HookType::INDEXEDDB_ADD;
    if (str == "BLOB_CREATE") return HookType::BLOB_CREATE;
    if (str == "FILE_CREATE") return HookType::FILE_CREATE;
    if (str == "URL_CREATE_OBJECT_URL") return HookType::URL_CREATE_OBJECT_URL;
    if (str == "CRYPTO_ENCRYPT") return HookType::CRYPTO_ENCRYPT;
    if (str == "CRYPTO_DECRYPT") return HookType::CRYPTO_DECRYPT;
    if (str == "CRYPTO_IMPORT_KEY") return HookType::CRYPTO_IMPORT_KEY;

    // Medium Priority
    if (str == "NAVIGATOR_SEND_BEACON") return HookType::NAVIGATOR_SEND_BEACON;
    if (str == "SHADOW_DOM_ATTACH") return HookType::SHADOW_DOM_ATTACH;
    if (str == "WASM_INSTANTIATE") return HookType::WASM_INSTANTIATE;
    if (str == "WASM_COMPILE") return HookType::WASM_COMPILE;
    if (str == "MUTATION_OBSERVER_CREATE") return HookType::MUTATION_OBSERVER_CREATE;
    if (str == "MUTATION_OBSERVER_OBSERVE") return HookType::MUTATION_OBSERVER_OBSERVE;
    if (str == "SESSION_STORAGE_SET") return HookType::SESSION_STORAGE_SET;
    if (str == "SESSION_STORAGE_GET") return HookType::SESSION_STORAGE_GET;

    // Low Priority
    if (str == "NOTIFICATION_CREATE") return HookType::NOTIFICATION_CREATE;
    if (str == "NOTIFICATION_PERMISSION") return HookType::NOTIFICATION_PERMISSION;
    if (str == "GEOLOCATION_GET") return HookType::GEOLOCATION_GET;
    if (str == "GEOLOCATION_WATCH") return HookType::GEOLOCATION_WATCH;
    if (str == "CLIPBOARD_WRITE") return HookType::CLIPBOARD_WRITE;
    if (str == "CLIPBOARD_READ") return HookType::CLIPBOARD_READ;
    if (str == "WEBRTC_CREATE") return HookType::WEBRTC_CREATE;
    if (str == "WEBRTC_DATA_CHANNEL") return HookType::WEBRTC_DATA_CHANNEL;
    if (str == "RAF_CREATE") return HookType::RAF_CREATE;
    if (str == "CONSOLE_LOG") return HookType::CONSOLE_LOG;
    if (str == "CONSOLE_WARN") return HookType::CONSOLE_WARN;
    if (str == "CONSOLE_ERROR") return HookType::CONSOLE_ERROR;

    // Detection 이름
    if (str == "OBFUSCATION_CHAINS") return HookType::OBFUSCATION_CHAINS;
    if (str == "ATTACK_CHAIN") return HookType::ATTACK_CHAIN;
    if (str == "JAVASCRIPT_CODE_IN_VARIABLE") return HookType::JAVASCRIPT_CODE_IN_VARIABLE;
    if (str == "HTML_CODE_IN_VARIABLE") return HookType::HTML_CODE_IN_VARIABLE;
    if (str == "MALICIOUS_PATTERN") return HookType::MALICIOUS_PATTERN;
    if (str == "MALICIOUS_PATTERN_BLOCKED") return HookType::MALICIOUS_PATTERN_BLOCKED;
    if (str == "DECODING_CHAIN") return HookType::DECODING_CHAIN;
    if (str == "OBFUSCATED_VARIABLES") return HookType::OBFUSCATED_VARIABLES;
    if (str == "ARRAY_OBFUSCATION") return HookType::ARRAY_OBFUSCATION;
    if (str == "LARGE_ENCODED_DATA") return HookType::LARGE_ENCODED_DATA;
    if (str == "ANTI_ANALYSIS") return HookType::ANTI_ANALYSIS;
    if (str == "IIFE_OBFUSCATION") return HookType::IIFE_OBFUSCATION;
    if (str == "SUSPICIOUS_CODE") return HookType::SUSPICIOUS_CODE;
    if (str == "INDIRECT_PROPERTY_ACCESS") return HookType::INDIRECT_PROPERTY_ACCESS;
    if (str == "SUSPICIOUS_VARIABLE") return HookType::SUSPICIOUS_VARIABLE;
    if (str == "SUSPICIOUS_TRACKED_STRING") return HookType::SUSPICIOUS_TRACKED_STRING;
    if (str == "CLIPBOARD_API") return HookType::CLIPBOARD_API;
    if (str == "MALICIOUS_COMMAND") return HookType::MALICIOUS_COMMAND;
    if (str == "SCRIPT_INJECTION") return HookType::SCRIPT_INJECTION;
    if (str == "REMOTE_MALICIOUS_FILE") return HookType::REMOTE_MALICIOUS_FILE;
    if (str == "CLIPBOARD_HIJACKING") return HookType::CLIPBOARD_HIJACKING;
    if (str == "ACTIVEX_USAGE") return HookType::ACTIVEX_USAGE;
    if (str == "WSCRIPT_USAGE") return HookType::WSCRIPT_USAGE;
    if (str == "STATIC_FINDING") return HookType::STATIC_FINDING;

    // Feature 키
    if (str == "ATTACK_CHAINS") return HookType::ATTACK_CHAINS;
    if (str == "SUMMARY") return HookType::SUMMARY;
    if (str == "INDIRECT_ACCESS_SUMMARY") return HookType::INDIRECT_ACCESS_SUMMARY;
    if (str == "INDIRECT_ACCESS_COUNT") return HookType::INDIRECT_ACCESS_COUNT;
    if (str == "INDIRECT_ACCESS_") return HookType::INDIRECT_ACCESS_PREFIX;
    if (str == "CRYPTO_OPERATION_") return HookType::CRYPTO_OPERATION_PREFIX;
    if (str == "FUNCTION_CALL_") return HookType::FUNCTION_CALL_PREFIX;
    if (str == "STRING_TRACKING_COUNT") return HookType::STRING_TRACKING_COUNT;
    if (str == "STRING_TRACKING_") return HookType::STRING_TRACKING_PREFIX;
    if (str == "TOTAL_CHAINS") return HookType::TOTAL_CHAINS;
    if (str == "HIGHEST_SEVERITY") return HookType::HIGHEST_SEVERITY;
    if (str == "EVENT_COUNT") return HookType::EVENT_COUNT;
    if (str == "EVAL_DETECTED") return HookType::EVAL_DETECTED;
    if (str == "REDIRECT_COUNT") return HookType::REDIRECT_COUNT;
    if (str == "REDIRECT_") return HookType::REDIRECT_PREFIX;
    if (str == "DETECTION_COUNT") return HookType::DETECTION_COUNT;
    if (str == "CHAIN_") return HookType::CHAIN_PREFIX;
    if (str == "FETCH_REQUEST_SUMMARY") return HookType::FETCH_REQUEST_SUMMARY;
    if (str == "TAINT_PATTERNS_SUMMARY") return HookType::TAINT_PATTERNS_SUMMARY;
    if (str == "DURATION_MS") return HookType::DURATION_MS;
    if (str == "TIME_RANGE") return HookType::TIME_RANGE;
    if (str == "THREATS") return HookType::THREATS;
    if (str == "EXTERNAL_") return HookType::EXTERNAL_PREFIX;
    if (str == "SCAN_TARGET") return HookType::SCAN_TARGET;
    if (str == "EXTERNAL_COUNT") return HookType::EXTERNAL_COUNT;
    if (str == "CRITICAL_COUNT") return HookType::CRITICAL_COUNT;
    if (str == "MANIPULATION_COUNT") return HookType::MANIPULATION_COUNT;
    if (str == "MANIPULATION_") return HookType::MANIPULATION_PREFIX;
    if (str == "PROPERTY_COUNT") return HookType::PROPERTY_COUNT;
    if (str == "DETECTED_") return HookType::DETECTED_PREFIX;
    if (str == "CHAIN_COUNT") return HookType::CHAIN_COUNT;

    return HookType::FUNCTION_CALL; // Default
}

// Helper function to map reason string to HookType and severity
inline std::pair<HookType, int> ReasonToDetectionType(const std::string& reason) {
    if (reason == "javascript_code_in_variable") return {HookType::JAVASCRIPT_CODE_IN_VARIABLE, 7};
    if (reason == "html_code_in_variable") return {HookType::HTML_CODE_IN_VARIABLE, 6};
    if (reason == "malicious_pattern_detected") return {HookType::MALICIOUS_PATTERN, 9};
    if (reason == "malicious_pattern_blocked") return {HookType::MALICIOUS_PATTERN_BLOCKED, 10};
    if (reason == "decoding_chain_detected") return {HookType::DECODING_CHAIN, 8};
    if (reason == "obfuscated_variables") return {HookType::OBFUSCATED_VARIABLES, 7};
    if (reason == "array_obfuscation") return {HookType::ARRAY_OBFUSCATION, 7};
    if (reason == "large_encoded_data") return {HookType::LARGE_ENCODED_DATA, 8};
    if (reason == "anti_analysis_detected") return {HookType::ANTI_ANALYSIS, 9};
    if (reason == "iife_obfuscation") return {HookType::IIFE_OBFUSCATION, 6};
    if (reason == "suspicious_variable_content") return {HookType::SUSPICIOUS_VARIABLE, 7};
    if (reason == "suspicious_tracked_string") return {HookType::SUSPICIOUS_TRACKED_STRING, 6};
    if (reason == "clipboard_api") return {HookType::CLIPBOARD_API, 7};
    if (reason == "malicious_command") return {HookType::MALICIOUS_COMMAND, 9};
    if (reason == "script_injection") return {HookType::SCRIPT_INJECTION, 9};
    if (reason == "remote_malicious_file") return {HookType::REMOTE_MALICIOUS_FILE, 10};
    if (reason == "clipboard_hijacking") return {HookType::CLIPBOARD_HIJACKING, 10};
    if (reason == "activex_usage") return {HookType::ACTIVEX_USAGE, 9};
    if (reason == "wscript_usage") return {HookType::WSCRIPT_USAGE, 9};
    
    // Default fallback
    return {HookType::STATIC_FINDING, 3};
}
