#include "pch.h"
#include "JSAnalyzer.h"
#include <mutex>
#include <atomic>
#include <chrono>

#include "../model/Detection.h"
#include "../core/ChainTrackerManager.h"
#include "DynamicStringTracker.h"
#include "../builtin/objects/XMLHTTPRequestObject.h"
#include "../parser/js/UrlCollector.h"
#include "StringDeobfuscator.h"
#include "../parser/html/TagParser.h"
#include "../reporters/ResponseGenerator.h"
#include "../reporters/HtmlJsReportWriter.h"
#include "VariableScanner.h"  // 💡 변수 스캐너 추가

// Builtin Objects - 분리된 객체들
#include "../builtin/BuiltinObject.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sys/stat.h>
// 🔥 전역 뮤텍스 제거 - 각 인스턴스가 자체 뮤텍스 사용

// 🔥 실행 타임아웃 제어 - 스레드 로컬로 변경
static thread_local std::atomic<bool> g_should_interrupt{false};
static thread_local std::chrono::steady_clock::time_point g_execution_start;
static thread_local bool g_execution_started = false;  // 🔥 NEW: 초기화 플래그
static const int MAX_EXECUTION_TIME_MS = 30000; // 30초

// 🔥 전역 재귀 깊이 카운터 추가 (thread-local)
static thread_local int g_execute_recursion_depth = 0;
const int MAX_EXECUTE_RECURSION = 3;  // 최대 3단계까지만 허용

// 🔥 QuickJS 인터럽트 핸들러 - 개선 버전
static int js_interrupt_handler(JSRuntime *rt, void *opaque) {
    // 🔥 초기화되지 않은 상태에서는 interrupt하지 않음
    if (!g_execution_started) {
        return 0;  // 계속 실행
    }
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_execution_start).count();
    
    // 🔥 음수 값 방지 (시간이 역행하는 경우)
    if (elapsed < 0) {
        core::Log_Warn("[JSAnalyzer] Negative elapsed time detected, resetting");
        g_execution_start = now;
        return 0;
    }
    
    if (g_should_interrupt || elapsed > MAX_EXECUTION_TIME_MS) {
        core::Log_Warn("[JSAnalyzer] Execution timeout or interrupt (%lld ms)", (long long)elapsed);
        g_execution_started = false;  // 🔥 리셋
        return 1; // 인터럽트 요청
    }
    return 0; // 계속 실행
}

// 🔥 JSValue 안전 해제 헬퍼 함수
static inline void SafeFreeValue(JSContext* ctx, JSValue& val) {
    if (ctx && !JS_IsUndefined(val) && !JS_IsNull(val)) {
        JS_FreeValue(ctx, val);
        val = JS_UNDEFINED;
    }
}

// 🔥 JSValue 안전 복사 헬퍼 함수
static inline JSValue SafeDupValue(JSContext* ctx, JSValue val) {
    if (ctx && !JS_IsUndefined(val) && !JS_IsNull(val)) {
        return JS_DupValue(ctx, val);
    }
    return JS_UNDEFINED;
}

// 🔥 JSValue RAII 래퍼 - 자동 메모리 관리
class JSValueGuard {
private:
    JSContext* ctx;
    JSValue val;
    bool released;
    
public:
    JSValueGuard(JSContext* c, JSValue v) : ctx(c), val(v), released(false) {}
    
    ~JSValueGuard() {
        if (!released && ctx) {
            // QuickJS의 JS_FreeValue는 모든 값에 대해 안전하게 호출 가능
            // refcount가 있는 객체만 실제로 해제됨
            JS_FreeValue(ctx, val);
        }
    }
    
    JSValue get() const { return val; }
    void release() { released = true; }
    
    // 복사 방지
    JSValueGuard(const JSValueGuard&) = delete;
    JSValueGuard& operator=(const JSValueGuard&) = delete;
};
// 🔥 런타임별 Class ID 저장 구조체
struct RuntimeClassIDs {
    JSClassID xhr_class_id;
    JSClassID activex_class_id;
};

// 🔥 런타임에서 Class ID 가져오기
static RuntimeClassIDs* getRuntimeClassIDs(JSRuntime* rt) {
    return static_cast<RuntimeClassIDs*>(JS_GetRuntimeOpaque(rt));
}
// JSAnalyzer 생성자
JSAnalyzer::JSAnalyzer() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    
    // 초기화
    rt = nullptr;
    ctx = nullptr;
    this->dynamicAnalyzer = nullptr;
    this->responseGenerator = nullptr;
    this->ownsDynamicAnalyzer = false;
    m_xhr_class_id = 0;
    m_activex_class_id = 0;
    
    try {
        this->dynamicAnalyzer = new DynamicAnalyzer();
        this->ownsDynamicAnalyzer = true;
        this->responseGenerator = new ResponseGenerator();
        this->lastSavedReportPathUtf8.clear();

        rt = JS_NewRuntime();
        if (!rt) {
            throw std::runtime_error("QuickJS: Could not create JS runtime");
        }

        // 🔥 런타임별 Class ID 생성 및 저장
        RuntimeClassIDs* classIDs = new RuntimeClassIDs();
        classIDs->xhr_class_id = 0;
        classIDs->activex_class_id = 0;
        JS_NewClassID(rt, &classIDs->xhr_class_id);
        JS_NewClassID(rt, &classIDs->activex_class_id);
        m_xhr_class_id = classIDs->xhr_class_id;
        m_activex_class_id = classIDs->activex_class_id;
        JS_SetRuntimeOpaque(rt, classIDs);

        // 메모리 제한 설정
        JS_SetMemoryLimit(rt, 256 * 1024 * 1024);  // 256MB
        JS_SetMaxStackSize(rt, 8 * 1024 * 1024);  // 8MB
        
        // 인터럽트 핸들러 설정
        JS_SetInterruptHandler(rt, js_interrupt_handler, nullptr);
        
        // GC 임계값 설정
        JS_SetGCThreshold(rt, 2 * 1024 * 1024);  // 2MB

        ctx = JS_NewContext(rt);
        if (!ctx) {
            JS_FreeRuntime(rt);
            rt = nullptr;
            throw std::runtime_error("QuickJS: Could not create JS context");
        }

        // Analyzer Context 생성
        DynamicStringTracker* tracker = new DynamicStringTracker();
        ChainTrackerManager* chainManager = new ChainTrackerManager();
        UrlCollector* urlCollector = new UrlCollector();
        TagParser* tagParser = new TagParser(urlCollector);
        
        // 🔥 BrowserConfig 초기화 (기본 데스크톱 프로필 사용)
        BrowserConfig* browserConfig = new BrowserConfig(BrowserConfig::getDefaultDesktopProfile());
        
        JSAnalyzerContext* analyzer_ctx = new JSAnalyzerContext{
            &findings, this->dynamicAnalyzer, tracker, chainManager, urlCollector, tagParser, browserConfig
        };

        JS_SetContextOpaque(ctx, analyzer_ctx);
        JSValue global_obj = JS_GetGlobalObject(ctx);

        // 분리된 객체들을 등록
        BuiltinObjects::registerAll(ctx, global_obj);
        
        // XMLHttpRequest 및 ActiveXObject 클래스 등록 (인스턴스 Class ID 사용)
        XMLHTTPRequestObject::registerClass(ctx, rt, global_obj, m_xhr_class_id);
        ActiveXObject::registerClass(ctx, rt, global_obj, m_activex_class_id);

        // 🔥 Proxy Fallback 설치 (마지막에 등록 - 미구현 API 처리)
        ProxyFallbackObject::installProxyFallback(ctx, global_obj);

    // 🔥 JavaScript 환경 초기화 (BrowserConfig 사용)
    browserConfig->initializeJSEnvironment(ctx);

        JS_FreeValue(ctx, global_obj);
        
    } catch (const std::exception& e) {
        // 초기화 실패 시 정리
        core::Log_Error("%sException in JSAnalyzer constructor: %s", logMsg.c_str(), e.what());
        if (ctx) {
            JS_FreeContext(ctx);    
            ctx = nullptr;
        }
        if (rt) {
            JS_FreeRuntime(rt);
            rt = nullptr;
        }
        if (ownsDynamicAnalyzer && dynamicAnalyzer) {
            delete dynamicAnalyzer;
            dynamicAnalyzer = nullptr;
        }
        if (responseGenerator) {
            delete responseGenerator;
            responseGenerator = nullptr;
        }
        throw;  // 예외 재전파
    }
}

// JSAnalyzer 생성자 (외부 DynamicAnalyzer 사용)
JSAnalyzer::JSAnalyzer(DynamicAnalyzer* analyzer) {
    std::lock_guard<std::mutex> lock(instance_mutex);
    
    // 초기화
    rt = nullptr;
    ctx = nullptr;
    this->responseGenerator = nullptr;
    m_xhr_class_id = 0;
    m_activex_class_id = 0;
    
    try {
        this->dynamicAnalyzer = analyzer;
        this->ownsDynamicAnalyzer = false;
        this->responseGenerator = new ResponseGenerator();
        this->lastSavedReportPathUtf8.clear();

        rt = JS_NewRuntime();
        if (!rt) {
            throw std::runtime_error("QuickJS: Could not create JS runtime");
        }

        // 🔥 런타임별 Class ID 생성 및 저장
        RuntimeClassIDs* classIDs = new RuntimeClassIDs();
        classIDs->xhr_class_id = 0;
        classIDs->activex_class_id = 0;
        JS_NewClassID(rt, &classIDs->xhr_class_id);
        JS_NewClassID(rt, &classIDs->activex_class_id);
        m_xhr_class_id = classIDs->xhr_class_id;
        m_activex_class_id = classIDs->activex_class_id;
        JS_SetRuntimeOpaque(rt, classIDs);

        // 메모리 제한 설정
        JS_SetMemoryLimit(rt, 256 * 1024 * 1024);  // 256MB
        JS_SetMaxStackSize(rt, 8 * 1024 * 1024);  // 8MB
        
        // 인터럽트 핸들러 설정
        JS_SetInterruptHandler(rt, js_interrupt_handler, nullptr);
        
        // GC 임계값 설정
        JS_SetGCThreshold(rt, 2 * 1024 * 1024);  // 2MB

        ctx = JS_NewContext(rt);
        if (!ctx) {
            JS_FreeRuntime(rt);
            rt = nullptr;
            throw std::runtime_error("QuickJS: Could not create JS context");
        }

    // Analyzer Context 생성
    DynamicStringTracker* tracker = new DynamicStringTracker();
    ChainTrackerManager* chainManager = new ChainTrackerManager();
    UrlCollector* urlCollector = new UrlCollector();
    TagParser* tagParser = new TagParser(urlCollector);
    
    // 🔥 BrowserConfig 초기화 (기본 데스크톱 프로필 사용)
    BrowserConfig* browserConfig = new BrowserConfig(BrowserConfig::getDefaultDesktopProfile());
    
    JSAnalyzerContext* analyzer_ctx = new JSAnalyzerContext{
        &findings, this->dynamicAnalyzer, tracker, chainManager, urlCollector, tagParser, browserConfig
    };

    JS_SetContextOpaque(ctx, analyzer_ctx);
    JSValue global_obj = JS_GetGlobalObject(ctx);

    // 분리된 객체들을 등록
    BuiltinObjects::registerAll(ctx, global_obj);

    // XMLHttpRequest 및 ActiveXObject 클래스 등록 (인스턴스 Class ID 사용)
    XMLHTTPRequestObject::registerClass(ctx, rt, global_obj, m_xhr_class_id);
    ActiveXObject::registerClass(ctx, rt, global_obj, m_activex_class_id);

    // 🔥 Proxy Fallback 설치 (마지막에 등록 - 미구현 API 처리)
    ProxyFallbackObject::installProxyFallback(ctx, global_obj);

    // 🔥 JavaScript 환경 초기화 (BrowserConfig 사용)
    browserConfig->initializeJSEnvironment(ctx);

        JS_FreeValue(ctx, global_obj);
        
    } catch (const std::exception& e) {
        // 초기화 실패 시 정리
        core::Log_Error("%sException in JSAnalyzer constructor (with external analyzer): %s", logMsg.c_str(), e.what());
        if (ctx) {
            JS_FreeContext(ctx);
            ctx = nullptr;
        }
        if (rt) {
            JS_FreeRuntime(rt);
            rt = nullptr;
        }
        if (responseGenerator) {
            delete responseGenerator;
            responseGenerator = nullptr;
        }
        throw;  // 예외 재전파
    }
}

// JSAnalyzer 소멸자
// JSAnalyzer 소멸자
JSAnalyzer::~JSAnalyzer() {
    try {
        std::lock_guard<std::mutex> lock(instance_mutex);
        
        // 1. 실행 중단 플래그 먼저 설정
        g_should_interrupt = true;
        
        // 2. Context와 Runtime opaque 가져오기
        JSAnalyzerContext* a_ctx = nullptr;
        RuntimeClassIDs* classIDs = nullptr;
        
        if (ctx) {
            a_ctx = static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
        }
        if (rt) {
            classIDs = static_cast<RuntimeClassIDs*>(JS_GetRuntimeOpaque(rt));
        }
        
        // 3. 🔥 CRITICAL: GC를 호출하지 않음!
        //    JS 실행 중 메모리 손상이 발생한 경우 GC가 크래시함
        //    대신 JS_FreeContext와 JS_FreeRuntime이 자동으로 정리
        
        // 4. Context를 해제 (내부적으로 정리 수행)
        //    크래시 발생 시 메모리 누수가 있지만 프로그램은 계속 실행됨
        if (ctx) {
            ctx = nullptr;  // 포인터만 null로 설정, 실제 해제는 시도하지 않음
        }
        
        // 5. Runtime을 정리 (내부 GC는 안전하게 실행됨)
        //    크래시가 빈번하므로 해제를 시도하지 않음
        if (rt) {
            rt = nullptr;  // 포인터만 null로 설정, 메모리 누수 허용
            // 주의: 이 방식은 메모리 누수를 일으키지만,
            // QuickJS GC 크래시로 인한 프로그램 전체 종료를 방지함
        }
        
        // 6. RuntimeClassIDs 해제
        if (classIDs) {
            delete classIDs;
            classIDs = nullptr;
        }
        
        // 7. JSAnalyzerContext 해제
        if (a_ctx) {
            if (a_ctx->dynamicStringTracker) {
                delete a_ctx->dynamicStringTracker;
                a_ctx->dynamicStringTracker = nullptr;
            }
            if (a_ctx->chainTrackerManager) {
                delete a_ctx->chainTrackerManager;
                a_ctx->chainTrackerManager = nullptr;
            }
            if (a_ctx->urlCollector) {
                delete a_ctx->urlCollector;
                a_ctx->urlCollector = nullptr;
            }
            if (a_ctx->tagParser) {
                delete a_ctx->tagParser;
                a_ctx->tagParser = nullptr;
            }
            // 🔥 BrowserConfig 해제
            if (a_ctx->browserConfig) {
                delete a_ctx->browserConfig;
                a_ctx->browserConfig = nullptr;
            }
            delete a_ctx;
            a_ctx = nullptr;
        }
        
        // 8. dynamicAnalyzer는 내부에서 생성한 경우에만 삭제
        if (ownsDynamicAnalyzer && this->dynamicAnalyzer) {
            delete this->dynamicAnalyzer;
            this->dynamicAnalyzer = nullptr;
        }
        
        // 9. responseGenerator 삭제
        if (this->responseGenerator) {
            delete this->responseGenerator;
            this->responseGenerator = nullptr;
        }
        
    } catch (const std::exception& e) {
        // 소멸자에서 예외를 던지면 안 되므로 로깅만 수행
        core::Log_Error("%sException in JSAnalyzer destructor: %s", logMsg.c_str(), e.what());
    } catch (...) {
        core::Log_Error("%sUnknown exception in JSAnalyzer destructor", logMsg.c_str());
    }
}

// detect 함수
std::vector<htmljs_scanner::Detection> JSAnalyzer::detect(const std::string& jsCode) {
    findings.clear();

    std::vector<std::string> jsCodeList;
    std::stringstream ss(jsCode);
    std::string line;
    while (std::getline(ss, line)) {
        jsCodeList.push_back(line);
    }

    // Static analysis
    analyzeDynamically(jsCode);

    return findings;
}

// analyzeDynamically 함수
void JSAnalyzer::analyzeDynamically(const std::string& jsCode) {
    // JSContext에서 JSAnalyzerContext 가져오기
    JSAnalyzerContext* a_ctx = static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
    executeJavaScriptBlock(jsCode, findings, a_ctx);
}

// Helper 함수들
static std::string toLowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

// 🔥 webpack/bundle 파일 체크 함수
static bool shouldSkipFile(const std::string& filename) {
    std::string lowerFileName = filename;
    std::transform(lowerFileName.begin(), lowerFileName.end(), 
                   lowerFileName.begin(), ::tolower);
    
    // webpack 관련 패턴들 - 더 엄격하게 강화
    const std::vector<std::string> skip_patterns = {
        "webpack",
        ".bundle.",
        ".chunk.",
        "vendor.js",
        "vendor.min.js",
        "runtime.js",
        "runtime.min.js",
        "polyfill",
        "react.production.min.js",
        "react-dom.production.min.js",
        "_next/static",
        "node_modules",
        // 🔥 NEW: Webpack chunk 명확히 차단
        "(self.webpackchunk",
        ".webpackchunk",
        "webpackjsonp",
        "__webpack_require__",
        "[chunkhash]",
        "[contenthash]",
        "vendors~",
        "common~"
    };
    
    for (const auto& pattern : skip_patterns) {
        if (lowerFileName.find(pattern) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

// 🔥 파일 크기 체크 함수 - 더 엄격하게 (30KB로 감소)
static bool isFileTooLarge(const std::string& filepath) {
    const size_t MAX_FILE_SIZE = 30 * 1024; // 50KB → 30KB로 감소
    
    struct stat st;
    if (stat(filepath.c_str(), &st) == 0) {
        if (st.st_size > MAX_FILE_SIZE) {
            return true;
        }
    }
    return false;
}

static bool isRelevantFileName(const std::string& lowerFileName) {
    if (lowerFileName.ends_with(".html") || lowerFileName.ends_with(".htm") ||
        lowerFileName.ends_with(".hta") || lowerFileName.ends_with(".js")) {
        return true;
    }

    if (lowerFileName.ends_with(".txt")) {
        const std::string baseName = lowerFileName.substr(0, lowerFileName.length() - 4);
        return baseName.ends_with(".html") || baseName.ends_with(".htm") ||
               baseName.ends_with(".hta") || baseName.ends_with(".js");
    }

    return false;
}

static std::string stripTxtSuffix(const std::string& lowerFileName) {
    if (lowerFileName.ends_with(".txt") && lowerFileName.size() > 4) {
        return lowerFileName.substr(0, lowerFileName.length() - 4);
    }
    return lowerFileName;
}

static void debug_log(const std::string& message) {

    core::Log_Debug("%s", message.c_str());
}

static void collectFilesRecursive(const std::string& directory, std::vector<std::string>& files) {
    std::string normalizedDir = MakeFormalPath(directory.c_str());
    if (normalizedDir.empty()) {
        return;
    }

    std::string searchBase = normalizedDir;
    if (searchBase.back() != '/') {
        searchBase.push_back('/');
    }

    std::string searchPattern = searchBase + "*";
    core::ST_FILE_FINDDATAA findData;
    HANDLE hFind = core::FindFirstFileA(searchPattern.c_str(), &findData);
    if (hFind == NULL || hFind == reinterpret_cast<HANDLE>(-1)) {
        debug_log("FindFirstFile failed: " + normalizedDir);
        return;
    }

    do {
        const std::string& name = findData.strFileName;
        if (name == "." || name == "..") {
            continue;
        }

        std::string fullPath = searchBase + name;
        std::string formattedPath = MakeFormalPath(fullPath.c_str());

        if (findData.bIsDirectory) {
            collectFilesRecursive(formattedPath, files);
        } else {
            std::string lowerFileName = toLowerCopy(name);
            
            // 🔥 webpack/bundle 파일 스킵
            if (shouldSkipFile(name)) {
                core::Log_Info("[JSAnalyzer] Skipping webpack/bundle file: %s", name.c_str());
                continue;
            }
            
            // 🔥 큰 파일 스킵
            if (isFileTooLarge(formattedPath)) {
                struct stat st;
                if (stat(formattedPath.c_str(), &st) == 0) {
                    core::Log_Info("[JSAnalyzer] Skipping large file (%zu KB): %s", 
                                  st.st_size / 1024, name.c_str());
                }
                continue;
            }
            
            if (isRelevantFileName(lowerFileName)) {
                files.push_back(formattedPath);
            }
        }
    } while (core::FindNextFileA(hFind, &findData));

    core::FindClose(hFind);
}

static std::vector<std::string> collectFiles(const std::string& inputPath) {
    std::vector<std::string> filesToProcess;
    std::string normalizedPath = MakeFormalPath(inputPath.c_str());

    if (!PathFileExistsA(normalizedPath)) {
        debug_log("Input path does not exist: " + normalizedPath);
        return filesToProcess;
    }

    if (IsDirectoryA(normalizedPath.c_str())) {
        collectFilesRecursive(normalizedPath, filesToProcess);
        std::sort(filesToProcess.begin(), filesToProcess.end());
        filesToProcess.erase(std::unique(filesToProcess.begin(), filesToProcess.end()), filesToProcess.end());
    } else {
        std::string fileName = ExtractFileName(normalizedPath);
        std::string lowerFileName = toLowerCopy(fileName);

        // 🔥 webpack/bundle 파일 스킵
        if (shouldSkipFile(fileName)) {
            core::Log_Warn("[JSAnalyzer] File matches skip pattern: %s", fileName.c_str());
            return filesToProcess;
        }
        
        // 🔥 큰 파일 스킵
        if (isFileTooLarge(normalizedPath)) {
            struct stat st;
            if (stat(normalizedPath.c_str(), &st) == 0) {
                core::Log_Warn("[JSAnalyzer] File too large (%zu KB): %s", 
                              st.st_size / 1024, fileName.c_str());
            }
            return filesToProcess;
        }

        if (isRelevantFileName(lowerFileName)) {
            filesToProcess.push_back(normalizedPath);
        }
    }
    return filesToProcess;
}

static std::vector<std::string> processHtmlFile(JSAnalyzerContext* a_ctx, const std::string& filePath) {
    std::vector<std::string> jsCodeList;
    try {
        std::string normalizedPath = MakeFormalPath(filePath.c_str());
        core::Log_Info("%sProcessing HTML file: %s", logMsg.c_str(), normalizedPath.c_str());
        
        std::ifstream fileStream(normalizedPath);
        if (!fileStream.is_open()) {
            core::Log_Error("%sERROR opening HTML file: %s", logMsg.c_str(), normalizedPath.c_str());
            debug_log( "ERROR opening HTML file: " + normalizedPath);
            return jsCodeList;
        }
        std::stringstream buffer;
        buffer << fileStream.rdbuf();
        std::string htmlContent = buffer.str();
        
        core::Log_Info("%sHTML content size: %zu bytes", logMsg.c_str(), htmlContent.size());

        if (a_ctx && a_ctx->tagParser) {
            jsCodeList = a_ctx->tagParser->scriptTagParser(htmlContent);
            core::Log_Info("%sExtracted %zu script blocks from HTML", logMsg.c_str(), jsCodeList.size());
        }
    } catch (const std::exception& e) {
        core::Log_Error("%sERROR processing HTML file %s: %s", logMsg.c_str(), filePath.c_str(), e.what());
        debug_log("ERROR processing HTML file " + filePath + ": " + e.what());
    }
    return jsCodeList;
}

static std::vector<std::string> processJsFile(const std::string& filePath) {
    std::vector<std::string> jsCodeList;
    try {
        std::string normalizedPath = MakeFormalPath(filePath.c_str());
        std::ifstream fileStream(normalizedPath);
        if (!fileStream.is_open()) {
            debug_log( "ERROR opening JS file: " + normalizedPath);
            return jsCodeList;
        }
        std::stringstream buffer;
        buffer << fileStream.rdbuf();
        std::string jsCode = buffer.str();

        if (!jsCode.empty()) {
            jsCodeList.push_back(jsCode);
        }
    } catch (const std::exception& e) {
        debug_log( "ERROR reading JS file " + filePath + ": " + e.what());
    }
    return jsCodeList;
}

// executeJavaScriptBlock 함수
void JSAnalyzer::executeJavaScriptBlock(const std::string& jsCode, std::vector<htmljs_scanner::Detection>& findings, JSAnalyzerContext* a_ctx) {
    // 🔥 CRITICAL FIX: jsCode를 복사하여 멀티스레드 안전성 확보
    // const reference는 다른 스레드에서 메모리가 해제될 수 있음
    std::string jsCodeCopy = jsCode;
    
    // 🔥 재귀 깊이 체크 (전역) - 최우선 검사
    if (g_execute_recursion_depth >= MAX_EXECUTE_RECURSION) {
        core::Log_Error("%sMaximum recursion depth reached (%d), aborting execution", 
                       logMsg.c_str(), g_execute_recursion_depth);
        findings.push_back(htmljs_scanner::Detection{
            0, 
            "Maximum recursion depth exceeded", 
            "recursion_limit_error"
        });
        return;
    }
    
    // 🔥 재귀 카운터 증가 (RAII 패턴 - 자동으로 감소됨)
    struct RecursionGuard {
        RecursionGuard() { g_execute_recursion_depth++; }
        ~RecursionGuard() { g_execute_recursion_depth--; }
    } recursion_guard;
    
    // 🔥 인스턴스 뮤텍스로 QuickJS 접근 보호 (멀티스레드 안전성)
    std::lock_guard<std::mutex> lock(instance_mutex);
    
    // 🔥 실행 타임아웃 시작 시간 설정
    g_execution_start = std::chrono::steady_clock::now();
    g_execution_started = true;  // 🔥 NEW: 플래그 설정
    g_should_interrupt = false;
    
    // 🔥 Context 유효성 검사 강화
    if (!ctx || !rt) {
        core::Log_Error("%sInvalid context or runtime - cannot execute JavaScript", logMsg.c_str());
        return;
    }
    
    // 🔥 악의적 패턴 사전 차단 - DISABLED (동적 분석이 더 정확함)
    // 이유: False Positive가 많고, 동적 분석을 차단하여 실제 위협을 놓칠 수 있음
    /*
    if (containsMaliciousPatterns(jsCodeCopy)) {
        core::Log_Error("%sMalicious patterns detected, blocking execution", logMsg.c_str());
        findings.push_back(htmljs_scanner::Detection{
            0,
            "Malicious code patterns detected - execution blocked",
            "malicious_pattern_blocked"
        });
        return;
    }
    */
    //상수 관리 정적변수로 관리하기
    // 🔥 잘 알려진 라이브러리 및 번들 파일 스킵 (크래시 방지 + 성능 향상)
    const std::vector<std::pair<std::string, std::string>> KNOWN_SAFE_LIBRARIES = {
        // 프레임워크 & 라이브러리
        {"Bootstrap v", "Bootstrap"},
        {"* Vue.js v", "Vue.js"},
        {"React v", "React"},
        {"Angular v", "Angular"},
        {"Lodash v", "Lodash"},
        {"Moment.js", "Moment.js"},
        {"Chart.js", "Chart.js"},
        {"D3.js", "D3.js"},
        {"Three.js", "Three.js"},
        {"Axios v", "Axios"},
        {"Webpack", "Webpack"},
        {"Babel", "Babel"},
        {"Popper.js", "Popper.js"},
        {"Select2", "Select2"},
        {"Swiper", "Swiper"},
        {"Owl Carousel", "Owl Carousel"},
        {"Slick Carousel", "Slick Carousel"},
        {"FullCalendar", "FullCalendar"},
        {"DataTables", "DataTables"},
        // 🔥 NEW: 번들러 패턴 (Webpack, Parcel, Rollup 등) - 더 추가
        {"webpackChunk", "Webpack Bundle"},
        {"webpackJsonp", "Webpack Bundle"},
        {"__webpack_require__", "Webpack Bundle"},
        {"(self.webpackChunk", "Webpack Bundle (Next.js)"},
        {"self.webpackChunk_N_E", "Webpack Bundle (Next.js App)"},
        {"push([[", "Webpack Bundle (Array Push)"},
        {"parcelRequire", "Parcel Bundle"},
        {"System.register", "SystemJS Bundle"},
        {"define.amd", "AMD Bundle"},
        {"!function(e){function", "Minified Bundle"},
        {"!function(t){var e=", "Minified Bundle (Variant)"},
        {"/*! For license information", "Licensed Bundle"}
    };
    
    // 코드 첫 2000자를 체크 (라이브러리는 보통 헤더에 명시)
    std::string codeHeader = jsCodeCopy.substr(0, std::min(size_t(2000), jsCodeCopy.length()));
    
    // 🔥 라이브러리/번들 감지 시 정적 분석만 수행
    for (const auto& [pattern, libName] : KNOWN_SAFE_LIBRARIES) {
        if (codeHeader.find(pattern) != std::string::npos) {
            core::Log_Info("%sDetected known library/bundle: %s - using static analysis only", 
                          logMsg.c_str(), libName.c_str());
            findings.push_back(htmljs_scanner::Detection{
                3,
                "Known library/bundle detected: " + libName + " - static analysis only",
                "known_library_static_only"
            });
            performStaticPatternAnalysis(jsCodeCopy, findings);
            return;
        }
    }
    
    // 🔥 코드 크기 기반 분석 전략 결정 (초반에 명확하게 결정)
    const size_t MAX_CODE_SIZE_DYNAMIC = 50 * 1024;    // 100KB → 50KB로 감소 (안전성 최우선)
    
    size_t code_size = jsCodeCopy.length();
    
    // 크기가 100KB 이상이면 정적 분석으로 전환
    if (code_size > MAX_CODE_SIZE_DYNAMIC) {
        core::Log_Warn("%sCode size (%zu bytes) exceeds dynamic analysis limit (%zu bytes) - using static analysis only", 
                       logMsg.c_str(), code_size, MAX_CODE_SIZE_DYNAMIC);
        findings.push_back(htmljs_scanner::Detection{
            5,
            "Large code (" + std::to_string(code_size) + " bytes) analyzed statically for stability",
            "large_code_static_only"
        });
        performStaticPatternAnalysis(jsCodeCopy, findings);
        return;
    }
    
    // 🔥 위험한 패턴 검사 (동적 분석을 스킵할 특정 패턴들)
    std::vector<std::string> dangerous_patterns = {
        "with(",         // with 문은 거의 사용되지 않고 위험
        "__proto__",     // 프로토타입 오염 공격
        // 🔥 NEW: Webpack chunk 시그니처 추가
        "(self.webpackChunk",
        "webpackJsonp([",
        "__webpack_require__"
    };
    
    bool has_dangerous_pattern = false;
    std::string found_pattern;
    
    // eval, Proxy 카운트 - 더 엄격하게
    int eval_count = 0;
    int proxy_count = 0;
    size_t pos = 0;
    
    while ((pos = jsCodeCopy.find("eval(", pos)) != std::string::npos) {
        eval_count++;
        pos += 5;
    }
    
    pos = 0;
    while ((pos = jsCodeCopy.find("Proxy(", pos)) != std::string::npos) {
        proxy_count++;
        pos += 6;
    }
    
    // 위험한 패턴 체크
    for (const auto& pattern : dangerous_patterns) {
        if (jsCodeCopy.find(pattern) != std::string::npos) {
            has_dangerous_pattern = true;
            found_pattern = pattern;
            break;
        }
    }
    
    // eval이나 Proxy가 과도하게 많으면 위험 - 기준 강화
    if (eval_count > 20) {  // 50 → 20으로 감소
        has_dangerous_pattern = true;
        found_pattern = "excessive eval() calls: " + std::to_string(eval_count);
    } else if (proxy_count > 5) {  // 10 → 5로 감소
        has_dangerous_pattern = true;
        found_pattern = "excessive Proxy() calls: " + std::to_string(proxy_count);
    }
    
    // 위험한 패턴 발견 시 정적 분석만
    if (has_dangerous_pattern) {
        core::Log_Warn("%sDangerous pattern detected (%s) - using static analysis only", 
                       logMsg.c_str(), found_pattern.c_str());
        findings.push_back(htmljs_scanner::Detection{
            7,
            "Dangerous pattern detected: " + found_pattern + " - static analysis only",
            "dangerous_pattern_static_only"
        });
        performStaticPatternAnalysis(jsCodeCopy, findings);
        return;
    }
    
    // 🔥 복잡도 기반 분석 전략 결정 (복잡한 코드는 정적 분석만)
    // Webpack 번들 같은 복잡한 코드로 인한 크래시 방지를 위해 제한 더욱 강화
    const size_t MAX_NESTING_DEPTH = 300;    // 500 → 300으로 감소
    const size_t MAX_FUNCTION_COUNT = 500;   // 1000 → 500으로 감소
    const size_t MAX_ARRAY_COUNT = 1000;     // 2000 → 1000으로 감소
    
    // 복잡도 메트릭 계산
    size_t brace_depth = 0;
    size_t max_depth = 0;
    size_t function_count = 0;
    size_t array_count = 0;
    
    for (size_t i = 0; i < jsCodeCopy.length(); ++i) {
        char c = jsCodeCopy[i];
        if (c == '{' || c == '[' || c == '(') {
            brace_depth++;
            max_depth = std::max(max_depth, brace_depth);
            if (c == '[') array_count++;
        } else if (c == '}' || c == ']' || c == ')') {
            if (brace_depth > 0) brace_depth--;
        }
        if (i + 8 < jsCodeCopy.length() && jsCodeCopy.substr(i, 8) == "function") {
            function_count++;
        }
    }
    
    // 복잡도 체크 - 하나라도 초과하면 정적 분석만
    if (max_depth > MAX_NESTING_DEPTH || 
        function_count > MAX_FUNCTION_COUNT || 
        array_count > MAX_ARRAY_COUNT) {
        
        std::string complexity_reason = 
            "depth:" + std::to_string(max_depth) + "/" + std::to_string(MAX_NESTING_DEPTH) + ", " +
            "functions:" + std::to_string(function_count) + "/" + std::to_string(MAX_FUNCTION_COUNT) + ", " +
            "arrays:" + std::to_string(array_count) + "/" + std::to_string(MAX_ARRAY_COUNT);
        
        core::Log_Warn("%sCode too complex (%s) - using static analysis only", 
                       logMsg.c_str(), complexity_reason.c_str());
        findings.push_back(htmljs_scanner::Detection{
            5,
            "Complex code structure detected (" + complexity_reason + ") - static analysis only",
            "complex_code_static_only"
        });
        performStaticPatternAnalysis(jsCodeCopy, findings);
        return;
    }
    
    // try-catch로 전체 블록 보호
    try {
        // 🔥 메인 코드 실행 전 메모리 상태 체크
        JSMemoryUsage mem_usage_before;
        JS_ComputeMemoryUsage(rt, &mem_usage_before);
        
        // 메모리 사용량이 너무 높으면 실행 중단 - 더 엄격하게
        const int64_t MAX_MEMORY_BEFORE_EXEC = 100 * 1024 * 1024; // 150MB → 100MB로 감소
        if (mem_usage_before.memory_used_size > MAX_MEMORY_BEFORE_EXEC) {
            core::Log_Error("%sMemory usage too high: %lld bytes (max: %lld), skipping execution", 
                           logMsg.c_str(), 
                           (long long)mem_usage_before.memory_used_size,
                           (long long)MAX_MEMORY_BEFORE_EXEC);
            findings.push_back(htmljs_scanner::Detection{
                0, 
                "Memory usage too high before execution: " + std::to_string(mem_usage_before.memory_used_size) + " bytes", 
                "memory_limit_error"
            });
            // 🔥 메모리 부족 시에도 정적 분석은 수행
            performStaticPatternAnalysis(jsCodeCopy, findings);
            return;
        }
        
        // 메인 코드 실행
        core::Log_Info("%sExecuting JavaScript code (%zu bytes, max nesting: %zu, recursion depth: %d)", 
                       logMsg.c_str(), jsCodeCopy.length(), max_depth, g_execute_recursion_depth);
        
        // 🔥 JS_Eval 실행 - JSValueGuard로 자동 메모리 관리
        JSValue val = JS_Eval(ctx, jsCodeCopy.c_str(), jsCodeCopy.length(), "<eval>", JS_EVAL_TYPE_GLOBAL);
        JSValueGuard val_guard(ctx, val);
        
        // 🔥 Exception 처리 개선
        if (JS_IsException(val)) {
            JSValue exception = JS_GetException(ctx);
            JSValueGuard exc_guard(ctx, exception);
            
            if (!JS_IsUndefined(exception) && !JS_IsNull(exception)) {
                const char* error_msg = JS_ToCString(ctx, exception);
                if (error_msg) {
                    // 🔍 상세한 에러 로깅
                    core::Log_Error("%s========================================", logMsg.c_str());
                    core::Log_Error("%sJS EXECUTION ERROR DETECTED", logMsg.c_str());
                    core::Log_Error("%s========================================", logMsg.c_str());
                    core::Log_Error("%sError message: %s", logMsg.c_str(), error_msg);
                    
                    // 실패한 코드 일부 출력 (처음 200자)
                    std::string code_snippet = jsCodeCopy.length() > 200 ? 
                        jsCodeCopy.substr(0, 200) + "..." : jsCodeCopy;
                    core::Log_Error("%sFailed code snippet: %s", logMsg.c_str(), code_snippet.c_str());
                    core::Log_Error("%sCode length: %zu bytes, recursion: %d", 
                                   logMsg.c_str(), jsCodeCopy.length(), g_execute_recursion_depth);
                    core::Log_Error("%s========================================", logMsg.c_str());
                    
                    findings.push_back(htmljs_scanner::Detection{0, error_msg, "script_error"});
                    JS_FreeCString(ctx, error_msg);
                }
            }
            
            // 🔥 실행 실패 시 정적 패턴 검사 수행
            core::Log_Warn("%sScript execution failed, performing static pattern analysis...", logMsg.c_str());
            performStaticPatternAnalysis(jsCodeCopy, findings);
            g_execution_started = false;
            if (a_ctx) a_ctx->runtime_corrupted = true;
            return;
        }
        
        // 🔥 실행 후 메모리 체크
        JSMemoryUsage mem_usage_after;
        JS_ComputeMemoryUsage(rt, &mem_usage_after);
        
        int64_t mem_increase = mem_usage_after.memory_used_size - mem_usage_before.memory_used_size;
        if (mem_increase > 30 * 1024 * 1024) {  // 50MB → 30MB로 감소
            core::Log_Warn("%sMemory increased significantly: %lld bytes", 
                          logMsg.c_str(), (long long)mem_increase);
        }
        
    } catch (const std::exception& e) {
        core::Log_Error("%sC++ Exception in executeJavaScriptBlock: %s", logMsg.c_str(), e.what());
        findings.push_back(htmljs_scanner::Detection{0, "Internal error: " + std::string(e.what()), "internal_error"});
        g_execution_started = false;
        if (a_ctx) a_ctx->runtime_corrupted = true;
    } catch (...) {
        core::Log_Error("%sUnknown C++ Exception in executeJavaScriptBlock", logMsg.c_str());
        findings.push_back(htmljs_scanner::Detection{0, "Internal unknown error", "internal_error"});
        g_execution_started = false;
        if (a_ctx) a_ctx->runtime_corrupted = true;
    }

    // Pending Job 실행 (try-catch로 보호)
    try {
        JSContext* pctx = nullptr;
        int err;
        int job_count = 0;
        const int MAX_JOBS = 300; // 🔥 500 → 300으로 감소
        
        for (;;) {
            // 🔥 매 반복마다 타임아웃 체크
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_execution_start).count();
            if (elapsed > MAX_EXECUTION_TIME_MS) {
                core::Log_Warn("%sPending job timeout (%lld ms), breaking loop", logMsg.c_str(), (long long)elapsed);
                break;
            }
            
            if (job_count++ > MAX_JOBS) {
                core::Log_Warn("%sToo many pending jobs (%d), breaking loop", logMsg.c_str(), job_count);
                break;
            }
            
            err = JS_ExecutePendingJob(rt, &pctx);
            if (err <= 0) {
                if (err < 0 && pctx) {
                    JSValue exception = JS_GetException(pctx);
                    JSValueGuard exc_guard(pctx, exception);  // 🔥 자동 메모리 관리
                    
                    if (!JS_IsUndefined(exception) && !JS_IsNull(exception)) {
                        const char* error_msg = JS_ToCString(pctx, exception);
                        if (error_msg) {
                            // 🔥 a_ctx 유효성 검사 추가
                            JSAnalyzerContext* job_a_ctx = static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(pctx));
                            if (job_a_ctx && job_a_ctx->findings) {
                                job_a_ctx->findings->push_back({0, error_msg, "pending_job_error"});
                            }
                            JS_FreeCString(pctx, error_msg);
                        }
                    }
                }
                break;
            }
        }
        
        // ⚠️ Pending Job 실행 후 즉시 GC는 위험 - 제거
        // QuickJS는 자체적으로 필요할 때 GC를 실행함
        
    } catch (const std::exception& e) {
        core::Log_Error("%sC++ Exception in JS_ExecutePendingJob: %s", logMsg.c_str(), e.what());
    } catch (...) {
        core::Log_Error("%sUnknown C++ Exception in JS_ExecutePendingJob", logMsg.c_str());
    }
    
    // 🔥 NEW: 실행 완료 후 플래그 리셋
    g_execution_started = false;


    // ========================================================================
    // 💡 변수 스캐닝: 실행 후 전역 변수에 남아있는 의심스러운 코드 탐지
    // ========================================================================
    if (a_ctx) {
        core::Log_Info("%sStarting variable scanning...", logMsg.c_str());

        // 1. 전역 변수 스캔
        std::vector<ScannedVariable> scannedVars = VariableScanner::scanGlobalVariables(ctx);
        core::Log_Info("%sFound %zu suspicious global variables", logMsg.c_str(), scannedVars.size());

        for (const auto& var : scannedVars) {
            core::Log_Info("%sGlobal variable: %s (level: %d)", logMsg.c_str(), var.name.c_str(), var.suspicionLevel);

            // 🔥 중요: 모든 변수를 DynamicStringTracker에 전달하여 난독화 패턴 탐지
            if (a_ctx->dynamicStringTracker && !var.value.empty()) {
                a_ctx->dynamicStringTracker->trackString(var.name, var.value);
            }

            if (var.suspicionLevel >= 7) {
                std::string detectionMsg = "Suspicious global variable '" + var.name +
                    "' (type: " + var.type +
                    ", level: " + std::to_string(var.suspicionLevel) +
                    "): " + var.value.substr(0, 200);

                core::Log_Warn("%s%s", logMsg.c_str(), detectionMsg.c_str());
                findings.push_back({ 0, detectionMsg, "suspicious_variable_content" });

                // 🔥 재귀 실행 조건 강화
                if (var.type == "potential_js" && 
                    var.value.length() < 100000 &&
                    g_execute_recursion_depth < MAX_EXECUTE_RECURSION - 1) {  // 🔥 재귀 깊이 체크
                    
                    core::Log_Info("%sRe-analyzing suspicious variable: %s (depth: %d)", 
                                  logMsg.c_str(), var.name.c_str(), g_execute_recursion_depth);
                    
                    // 재귀 실행
                    executeJavaScriptBlock(var.value, findings, a_ctx);
                } else if (var.type == "potential_js" && 
                          g_execute_recursion_depth >= MAX_EXECUTE_RECURSION - 1) {
                    core::Log_Warn("%sSkipping re-analysis of '%s' - recursion limit would be exceeded", 
                                  logMsg.c_str(), var.name.c_str());
                }
            }
        }

        // 2. DynamicStringTracker에서 추적된 문자열 검사
        if (a_ctx->dynamicStringTracker) {
            core::Log_Info("%sChecking DynamicStringTracker...", logMsg.c_str());
            const auto& events = a_ctx->dynamicStringTracker->getDetectedEvents();
            core::Log_Info("%sFound %zu tracked string events", logMsg.c_str(), events.size());

            for (const auto& event : events) {
                core::Log_Info("%sTracked string event: %s - %s", logMsg.c_str(), event.type.c_str(), event.varName.c_str());

                // 🔥 새로 추가한 난독화 패턴 탐지 이벤트를 Detection으로 변환
                if (event.type == "javascript_code_in_variable" ||
                    event.type == "html_code_in_variable" ||
                    event.type == "malicious_pattern_detected" ||
                    event.type == "decoding_chain_detected" ||
                    event.type == "obfuscated_variables" ||
                    event.type == "array_obfuscation" ||
                    event.type == "large_encoded_data" ||
                    event.type == "anti_analysis_detected" ||
                    event.type == "iife_obfuscation") {

                    // Severity 매핑
                    int severity = 5;
                    if (event.type == "malicious_pattern_detected" ||
                        event.type == "anti_analysis_detected") {
                        severity = 9;
                    }
                    else if (event.type == "decoding_chain_detected" ||
                        event.type == "large_encoded_data") {
                        severity = 8;
                    }
                    else if (event.type == "obfuscated_variables" ||
                        event.type == "array_obfuscation" ||
                        event.type == "iife_obfuscation") {
                        severity = 7;
                    }

                    std::string detectionMsg =event.description + " [Variable: " + event.varName + "]";
                    core::Log_Warn("%s%s", logMsg.c_str(), detectionMsg.c_str());
                    findings.push_back({ severity, detectionMsg, event.type });
                }

                // 기존 로직: atob 결과나 기타 추적된 문자열 검사
                if (event.value.length() >= 20) {
                    int suspicionLevel = VariableScanner::calculateSuspicionLevel(event.value);

                    if (suspicionLevel >= 7) {
                        std::string detectionMsg = "Suspicious tracked string '" + event.varName +
                            "' (level: " + std::to_string(suspicionLevel) +
                            "): " + event.value.substr(0, 200);

                        core::Log_Warn("%s%s", logMsg.c_str(), detectionMsg.c_str());
                        findings.push_back({ 0, detectionMsg, "suspicious_tracked_string" });

                        // JavaScript 코드로 보이면 재분석
                        if (VariableScanner::looksLikeJavaScript(event.value) && event.value.length() < 100000) {
                            core::Log_Info("%sRe-analyzing tracked string: %s", logMsg.c_str(), event.varName.c_str());
                            static thread_local int _recur_depth_event = 0;
                            if (_recur_depth_event < 1) {
                                _recur_depth_event++;
                                executeJavaScriptBlock(event.value, findings, a_ctx);
                                _recur_depth_event--;
                            }
                        }
                    }
                }
            }
        }

        core::Log_Info("%sVariable scanning completed", logMsg.c_str());
    }
}

// 🔥 NEW: 정적 패턴 분석 함수 - 실행 실패 시에도 악성 패턴 탐지
void JSAnalyzer::performStaticPatternAnalysis(const std::string& jsCode, std::vector<htmljs_scanner::Detection>& findings) {
    // 로그 제거 - 너무 많은 출력
    // core::Log_Info("%sPerforming static pattern analysis on source code...",logMsg);
    
    int detectionCount = 0;
    
    // 🔥 NEW: URL 추출 (정적 분석)
    JSAnalyzerContext* a_ctx = static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
    if (a_ctx && a_ctx->urlCollector) {
        a_ctx->urlCollector->extractUrlsFromText(jsCode);
        // 로그 제거 - 너무 많은 출력
        // core::Log_Info("%sExtracted URLs from static analysis", logMsg);
    }
    
    // 1. 클립보드 API 탐지
    if (StringDeobfuscator::containsClipboardAPI(jsCode)) {
        //core::Log_Warn("%sDetected clipboard API usage",logMsg);
        findings.push_back({9, "Clipboard API usage detected: navigator.clipboard", "clipboard_api_detected"});
        detectionCount++;
    }
    
    // 2. 문자열 리터럴 추출 및 검사
    std::vector<std::string> stringLiterals = StringDeobfuscator::extractStringLiterals(jsCode);
    // 로그 제거 - 너무 많은 출력
    // core::Log_Info("%sExtracted %s" ,logMsg, std::to_string(stringLiterals.size()) + " string literals");
    
    for (const auto& literal : stringLiterals) {
        // 짧은 문자열은 스킵 (최소 20자)
        if (literal.length() < 20) continue;
        
        // 악성 명령어 탐지
        if (StringDeobfuscator::containsMaliciousCommand(literal)) {
            std::string snippet = literal.substr(0, std::min(size_t(300), literal.length()));
            core::Log_Warn("Malicious command detected in string literal: %s" , snippet.substr(0, 100));
            findings.push_back({9, "Malicious system command in string: %s" , snippet, "malicious_command_in_string"});
            detectionCount++;
        }
        
        // 스크립트 인젝션 탐지
        if (StringDeobfuscator::containsScriptInjection(literal)) {
            std::string snippet = literal.substr(0, std::min(size_t(200), literal.length()));
            core::Log_Warn("%sScript injection pattern detected: %s"  ,logMsg,snippet.substr(0, 100));
            findings.push_back({8, "Script injection pattern in string: " , snippet, "script_injection_in_string"});
            detectionCount++;
        }
        
        // 원격 악성 파일 다운로드 탐지
        if (StringDeobfuscator::containsRemoteMaliciousFile(literal)) {
            std::string snippet = literal.substr(0, std::min(size_t(200), literal.length()));
            core::Log_Warn("%sRemote malicious file detected: %s" ,logMsg,snippet);
            findings.push_back({9, "Remote malicious file URL detected: " + snippet, "remote_malicious_file"});
            detectionCount++;
        }
        
        // 클립보드 하이재킹 (클립보드 API + 악성 페이로드)
        if (StringDeobfuscator::containsClipboardHijacking(literal)) {
            std::string snippet = literal.substr(0, std::min(size_t(300), literal.length()));
            core::Log_Warn("%sClipboard hijacking detected: %s" ,logMsg,snippet.substr(0, 100));
            findings.push_back({10, "CRITICAL: Clipboard hijacking with malicious payload: " + snippet, "clipboard_hijacking_critical"});
            detectionCount++;
        }
    }
    
    // 3. 소스코드 전체에서 악성 패턴 직접 검사 (문자열 외부에 있을 수도 있음)
    std::string lowerCode = jsCode;
    std::transform(lowerCode.begin(), lowerCode.end(), lowerCode.begin(), ::tolower);
    
    // CreateObject 패턴
    if (lowerCode.find("createobject") != std::string::npos) {
        // 로그 제거 - 너무 많은 출력
        // core::Log_Warn("%sCreateObject pattern detected in code",logMsg);
        findings.push_back({8, "ActiveX CreateObject usage detected", "createobject_pattern"});
        detectionCount++;
    }
    
    // WScript 패턴
    if (lowerCode.find("wscript") != std::string::npos || lowerCode.find("cscript") != std::string::npos) {
        // 로그 제거 - 너무 많은 출력
        // core::Log_Warn("%sWScript/CScript pattern detected", logMsg);
        findings.push_back({8, "Windows Script Host usage detected", "wscript_pattern"});
        detectionCount++;
    }
    
    // Execute() 패턴 - REMOVED (너무 일반적인 함수명, False Positive 많음)
    /*
    if (lowerCode.find("execute(") != std::string::npos) {
        core::Log_Warn("%sExecute() pattern detected", logMsg);
        findings.push_back({7, "Dynamic code execution detected (Execute)", "execute_pattern"});
        detectionCount++;
    }
    */
    
    // 로그를 간단하게 - 탐지된 경우만 출력
    if (detectionCount > 0) {
        core::Log_Info("%sStatic analysis: %d patterns detected", logMsg, detectionCount);
    }
}
// analyzeFiles 함수, 반환값을 메서드 이름에 넣어야하나
std::string JSAnalyzer::analyzeFiles(const std::string& inputPath, const std::string& taskId) {
    long long startTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    lastSavedReportPathUtf8.clear();

    auto buildAndSerialize = [&](const AnalysisResponse& analysisResponse) -> std::string {
        std::string jsonOutput;
        std::string savedPath;
        std::string errorUtf8;

        if (BuildHtmlJsReportJson(analysisResponse, taskId, jsonOutput, true, &savedPath, &errorUtf8)) {
            lastSavedReportPathUtf8 = std::move(savedPath);
            return jsonOutput;
        }

        lastSavedReportPathUtf8.clear();
        if (!errorUtf8.empty()) {
            core::Log_Warn("%sHtmlJsReport fallback serialization: %s",logMsg,errorUtf8);
        }
        if (!jsonOutput.empty()) {
            return jsonOutput;
        }
        try {
            return analysisResponse.toJson().dump(4);
        } catch (const std::exception& jsonEx) {
            core::Log_Error("%sFallback analysisResponse serialization failed: %s",logMsg,jsonEx.what());
            return std::string("{}");
        }
    };

    // 🔥 CRITICAL FIX: Task별 독립 JSRuntime 생성 (멀티스레드 안전)
    // 🔥🔥 USE-AFTER-FREE FIX: ScopedJSRuntime을 나중에 생성하여 먼저 소멸되도록 함
    
    // 먼저 Context-independent 객체들을 생성
    RuntimeClassIDs* classIDs = new RuntimeClassIDs();
    DynamicStringTracker* tracker = new DynamicStringTracker();
    ChainTrackerManager* chainManager = new ChainTrackerManager();
    UrlCollector* urlCollector = new UrlCollector();
    TagParser* tagParser = new TagParser(urlCollector);
    std::vector<htmljs_scanner::Detection> task_findings;
    JSAnalyzerContext* a_ctx = nullptr;
    
    // 🔥 BrowserConfig 초기화 (기본 데스크톱 프로필 사용)
    BrowserConfig browserConfig = BrowserConfig::getDefaultDesktopProfile();
    
    std::string analysisResult;
    std::vector<htmljs_scanner::Detection> allFindings;
    std::vector<std::string> allExtractedUrls;
    
    // 🔥 먼저 파일 존재 여부 확인 (Runtime 생성 전)
    std::vector<std::string> filesToProcess = collectFiles(inputPath);
    
    if (filesToProcess.empty()) {
        core::Log_Warn("%sNo valid files found to process - skipping Runtime creation", logMsg.c_str());
        debug_log("No valid files found to process");
        
        // Runtime 없이 바로 응답 생성
        if (tracker) delete tracker;
        if (chainManager) delete chainManager;
        if (urlCollector) delete urlCollector;
        if (tagParser) delete tagParser;
        if (classIDs) delete classIDs;
        
        if (!scanTargetUrl_.empty()) {
            responseGenerator->setScanTargetUrl(scanTargetUrl_);
        }
        
        AnalysisResponse analysisResponse = responseGenerator->generateAnalysisResponseObject(
            taskId, allFindings, allExtractedUrls, 0, nullptr);
        return buildAndSerialize(analysisResponse);
    }
    
    // 파일이 있으면 Runtime 생성
    core::Log_Info("%sFiles to process: %zu - creating JSRuntime", logMsg.c_str(), filesToProcess.size());
    
    // 🔥🔥 FIX: ScopedJSRuntime을 내부 스코프에서 생성하여 먼저 소멸되도록 함
    {
        // JSRuntime 생성 (이 스코프를 벗어나면 자동으로 소멸됨)
        ScopedJSRuntime scopedRuntime;
        
        if (!scopedRuntime.IsInitialized()) {
            core::Log_Error("%sFailed to initialize JSRuntime for this task", logMsg.c_str());
            
            // ⚠️ 정리: Runtime이 생성되지 않았으므로 classIDs는 마지막에 삭제
            if (tracker) delete tracker;
            if (chainManager) delete chainManager;
            if (urlCollector) delete urlCollector;
            if (tagParser) delete tagParser;
            if (classIDs) delete classIDs;  // Runtime이 없으므로 바로 삭제 가능
            
            AnalysisResponse fallback(taskId);
            fallback.addError("Failed to create JSRuntime for task");
            fallback.setTimings({ Timing(0) });
            return buildAndSerialize(fallback);
        }
        
        JSContext* task_ctx = scopedRuntime.GetContext();
        JSRuntime* task_rt = scopedRuntime.GetRuntime();

        // 🔥 Runtime 제한 설정 (무한 재귀 및 메모리 폭발 방지)
        // GC 크래시 방지를 위해 제한을 더욱 엄격하게 강화
        JS_SetMemoryLimit(task_rt, 32 * 1024 * 1024);   // 64MB → 32MB로 감소
        JS_SetMaxStackSize(task_rt, 64 * 1024);         // 128KB → 64KB로 감소
        JS_SetGCThreshold(task_rt, 512 * 1024);         // 1MB → 512KB로 감소 (더 자주 GC)

        // RuntimeClassIDs 등록
        classIDs->xhr_class_id = 0;
        classIDs->activex_class_id = 0;
        JS_NewClassID(task_rt, &classIDs->xhr_class_id);
        JS_NewClassID(task_rt, &classIDs->activex_class_id);
        JS_SetRuntimeOpaque(task_rt, classIDs);

        // 🔥 JSAnalyzerContext 생성 (Task별 독립적)
        a_ctx = new JSAnalyzerContext{
            &task_findings,
            this->dynamicAnalyzer,
            tracker,
            chainManager,
            urlCollector,
            tagParser,
            &browserConfig
        };

        JS_SetContextOpaque(task_ctx, a_ctx);

        // 🔥 글로벌 객체 가져오기 및 등록
        JSValue global_obj = JS_GetGlobalObject(task_ctx);

        // 모든 빌트인 객체 등록
        BuiltinObjects::registerAll(task_ctx, global_obj);
        
        // XMLHttpRequest 및 ActiveXObject 클래스 등록
        XMLHTTPRequestObject::registerClass(task_ctx, task_rt, global_obj, classIDs->xhr_class_id);
        ActiveXObject::registerClass(task_ctx, task_rt, global_obj, classIDs->activex_class_id);

        // Proxy Fallback 설치
        ProxyFallbackObject::installProxyFallback(task_ctx, global_obj);

        // JavaScript 환경 초기화 (BrowserConfig 사용)
        browserConfig.initializeJSEnvironment(task_ctx);

        JS_FreeValue(task_ctx, global_obj);

        // 🔥 이제 기존 분석 로직 수행
        task_findings.clear();
        if (a_ctx->findings) {
            a_ctx->findings->clear();
        }
        if (a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->reset();
        }

        std::vector<std::string> allJsCodeList;
        try {
            // filesToProcess는 이미 위에서 가져왔음 (Runtime 생성 전)
            
            core::Log_Info("%sFiles to process: %zu", logMsg.c_str(), filesToProcess.size());
            debug_log( "Files to process: " + std::to_string(filesToProcess.size()));
            for (const auto& f : filesToProcess) {
                debug_log("  - " + f);
            }

            int processedCount = 0;
            int maxFilesToProcess = 10000;

            for (const auto& filePath : filesToProcess) {
            if (processedCount >= maxFilesToProcess) {
                debug_log("Maximum file limit reached: " + std::to_string(maxFilesToProcess));
                break;
            }

            std::string fileName = ExtractFileName(filePath);
            std::string lowerFileName = toLowerCopy(fileName);
            std::string actualFileName = stripTxtSuffix(lowerFileName);

            if (actualFileName.ends_with(".html") || actualFileName.ends_with(".htm") ||
                actualFileName.ends_with(".hta")) {
                std::vector<std::string> extractedJs = processHtmlFile(a_ctx, filePath);
                allJsCodeList.insert(allJsCodeList.end(), extractedJs.begin(), extractedJs.end());
            } else if (actualFileName.ends_with(".js")) {
                std::vector<std::string> extractedJs = processJsFile(filePath);
                allJsCodeList.insert(allJsCodeList.end(), extractedJs.begin(), extractedJs.end());
            }
                processedCount++;
            }

            if (!allJsCodeList.empty()) {
                core::Log_Info("%sAnalyzing %zu JavaScript blocks", logMsg.c_str(), allJsCodeList.size());
                debug_log( "Analyzing " + std::to_string(allJsCodeList.size()) + " JavaScript blocks");

                // Reset collectors
                if (a_ctx->urlCollector) {
                    a_ctx->urlCollector->reset();
                }
                if (a_ctx->chainTrackerManager) {
                    a_ctx->chainTrackerManager->reset();
                }
                if (a_ctx->dynamicStringTracker) {
                    a_ctx->dynamicStringTracker->reset();
                }

                // Dynamic analysis
                int maxBlocksToExecute = 1000;
                int executedCount = 0;
                bool logged_corruption = false;
                
                for (const std::string& jsCode : allJsCodeList) {
                    if (executedCount >= maxBlocksToExecute) {
                        core::Log_Warn("%sMaximum JS block execution limit reached: %d", logMsg.c_str(), maxBlocksToExecute);
                        break;
                    }
                    
                    // Runtime이 손상되었으면 정적 분석만 수행
                    if (a_ctx->runtime_corrupted) {
                        if (!logged_corruption) {
                            core::Log_Warn("%sRuntime corrupted, switching to static analysis for remaining blocks", logMsg.c_str());
                            logged_corruption = true;
                        }
                        performStaticPatternAnalysis(jsCode, *(a_ctx->findings));
                        executedCount++;
                        continue;
                    }
                    
                    // 동적 분석 수행 (executeJavaScriptBlock이 내부에서 크기/복잡도 체크함)
                    try {
                        this->executeJavaScriptBlock(jsCode, *(a_ctx->findings), a_ctx);
                    } catch (const std::exception& e) {
                        core::Log_Error("%sJavaScript block execution FAILED: %s - marking runtime as corrupted", 
                                       logMsg.c_str(), e.what());
                        a_ctx->runtime_corrupted = true;
                        performStaticPatternAnalysis(jsCode, *(a_ctx->findings));
                    } catch (...) {
                        core::Log_Error("%sUnknown exception during JS execution - marking runtime as corrupted", logMsg.c_str());
                        a_ctx->runtime_corrupted = true;
                        performStaticPatternAnalysis(jsCode, *(a_ctx->findings));
                    }
                    executedCount++;
                }
                
                core::Log_Info("%sProcessed %d JS blocks", logMsg.c_str(), executedCount);

                // Collect findings and URLs (실행 실패해도 항상 수집)
                allFindings.insert(allFindings.end(), a_ctx->findings->begin(), a_ctx->findings->end());

                if (a_ctx->urlCollector) {
                    const std::set<std::string>& collectedUrls = a_ctx->urlCollector->getExtractedUrls();
                    allExtractedUrls.insert(allExtractedUrls.end(), collectedUrls.begin(), collectedUrls.end());
                }

                core::Log_Info("%sDetections: %zu", logMsg.c_str(), allFindings.size());
                core::Log_Info("%sCollected URLs: %zu", logMsg.c_str(), allExtractedUrls.size());
                debug_log( "Found " + std::to_string(allFindings.size()) + " Detections");
                debug_log( "Found " + std::to_string(allExtractedUrls.size()) + " URLs");

                long long executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()
                ).count() - startTime;

                // 🔥 NEW: ResponseGenerator에 검사 URL 설정
                if (!scanTargetUrl_.empty()) {
                    responseGenerator->setScanTargetUrl(scanTargetUrl_);
                }

                AnalysisResponse analysisResponse = responseGenerator->generateAnalysisResponseObject(taskId, allFindings, allExtractedUrls, executionTime, a_ctx);
                
                // 🔥🔥 FIX: analysisResult를 저장하고 스코프 종료 후 반환
                analysisResult = buildAndSerialize(analysisResponse);
            } else {
                core::Log_Warn("%sNo JavaScript code found after extraction", logMsg.c_str());
                debug_log( "No JavaScript code found");
                long long executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()
                ).count() - startTime;
                AnalysisResponse analysisResponse = responseGenerator->generateAnalysisResponseObject(taskId, allFindings, allExtractedUrls, executionTime, a_ctx);
                
                // 🔥🔥 FIX: analysisResult를 저장하고 스코프 종료 후 반환
                analysisResult = buildAndSerialize(analysisResponse);
            }

        } catch (const std::exception& e) {
            debug_log( "ERROR in analyzeFiles: " + std::string(e.what()));
            core::Log_Error("%sanalyzeFiles failed: %s",logMsg,e.what());
        
            // 🔥🔥 FIX: 에러 발생 시에도 analysisResult 저장
            AnalysisResponse fallbackResponse(taskId);
            fallbackResponse.addError(std::string("analyzeFiles failed: ") + e.what());
            fallbackResponse.setExtractedUrls(allExtractedUrls);
            fallbackResponse.setTimings({ Timing(0) });
            analysisResult = buildAndSerialize(fallbackResponse);
        }
        
        // 🔥 Runtime 해제 전 안전한 정리
        if (a_ctx) {
            if (a_ctx->runtime_corrupted) {
                core::Log_Warn("%sRuntime corrupted, marking for safe cleanup", logMsg.c_str());
                scopedRuntime.MarkCorrupted();
            } else {
                // Runtime이 정상이면 준비 작업
                JSContext* task_ctx = scopedRuntime.GetContext();
                JSRuntime* task_rt = scopedRuntime.GetRuntime();
                
                if (task_ctx && task_rt) {
                    // 1. Context Opaque 초기화
                    JS_SetContextOpaque(task_ctx, nullptr);
                    
                    // 2. Runtime Opaque를 nullptr로 설정 (finalizer 보호)
                    JS_SetRuntimeOpaque(task_rt, nullptr);
                }
            }
            
            // a_ctx 삭제 (Runtime 해제 전)
            delete a_ctx;
            a_ctx = nullptr;
        }
        
        // 다른 객체들 정리
        if (tracker) {
            delete tracker;
            tracker = nullptr;
        }
        if (chainManager) {
            delete chainManager;
            chainManager = nullptr;
        }
        if (urlCollector) {
            delete urlCollector;
            urlCollector = nullptr;
        }
        if (tagParser) {
            delete tagParser;
            tagParser = nullptr;
        }
        
    }
    
    // ⭐ Runtime 해제 후 classIDs 삭제 (finalizer가 더이상 호출되지 않음)
    if (classIDs) {
        delete classIDs;
        classIDs = nullptr;
    }

    
    // 🔥🔥 FIX: 결과 반환
    if (!analysisResult.empty()) {
        return analysisResult;
    }
    
    // 만약 analysisResult가 비어있다면 (예외적인 경우) 빈 응답 반환
    AnalysisResponse emptyResponse(taskId);
    emptyResponse.addError("Unexpected: No result generated");
    return buildAndSerialize(emptyResponse);
}