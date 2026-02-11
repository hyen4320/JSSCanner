#pragma once
#include "../parser/html/TagParser.h"
#include "DynamicStringTracker.h"
#include "DynamicAnalyzer.h"
#include "../parser/js/UrlCollector.h"
#include "StringDeobfuscator.h"
#include "../core/ChainTrackerManager.h"
#include "../core/BrowserConfig.h"
#include "../model/Detection.h"
#include "../quickjs.h"
#include "ScopedJSRuntime.h"  // 🔥 Task별 독립 JSRuntime
#include <string>
#include <mutex>

class ResponseGenerator;

struct JSAnalyzerContext {
    std::vector<htmljs_scanner::Detection>* findings;
    DynamicAnalyzer* dynamicAnalyzer;
    DynamicStringTracker* dynamicStringTracker;
    ChainTrackerManager* chainTrackerManager;
    UrlCollector* urlCollector;
    TagParser* tagParser;
    BrowserConfig* browserConfig;

    std::map<std::string, int> functionCallCounts;
    static const int MAX_FUNCTION_CALLS = 1000;
    bool analysisLimitExceeded = false;
    bool runtime_corrupted = false;
};

class JSAnalyzer {
public:
    JSAnalyzer();
    JSAnalyzer(DynamicAnalyzer* analyzer);
    JSAnalyzer(DynamicAnalyzer* analyzer, const BrowserConfig& config);  // 추가
    ~JSAnalyzer();

    void setBrowserConfig(const BrowserConfig& config);  // 추가
    const BrowserConfig& getBrowserConfig() const { return browserConfig; }  // 추가

    // 🔥 NEW: 검사 대상 URL 설정/조회
    void setScanTargetUrl(const std::string& url) { scanTargetUrl_ = url; }
    const std::string& getScanTargetUrl() const { return scanTargetUrl_; }

    std::vector<htmljs_scanner::Detection> detect(const std::string& input);
    std::vector<htmljs_scanner::Detection> detectFromHtml(const std::string& htmlContent);

    std::string analyzeFiles(const std::string& inputPath, const std::string& taskId);
    const std::string& getLastSavedReportPath() const { return lastSavedReportPathUtf8; }

private:
    JSRuntime* rt;
    JSContext* ctx;
    std::vector<htmljs_scanner::Detection> findings;
    DynamicAnalyzer* dynamicAnalyzer;
    ResponseGenerator* responseGenerator;
    std::string lastSavedReportPathUtf8;
    bool ownsDynamicAnalyzer;  // dynamicAnalyzer가 내부에서 생성되었는지 여부
    BrowserConfig browserConfig;  // 추가
    std::string scanTargetUrl_;  // 🔥 NEW: 검사 대상 URL
    
    // 🔥 인스턴스별 뮤텍스 (멀티스레드 안전성)
    std::mutex instance_mutex;
    
    // 🔥 인스턴스별 Class ID (멀티스레드 안전성)
    JSClassID m_xhr_class_id;
    JSClassID m_activex_class_id;

    void analyzeDynamically(const std::string& jsCode);
    void executeJavaScriptBlock(const std::string& jsCode, std::vector<htmljs_scanner::Detection>& findings, JSAnalyzerContext* a_ctx);
    void performStaticPatternAnalysis(const std::string& jsCode, std::vector<htmljs_scanner::Detection>& findings);
    
    // 🔥 클래스 등록 헬퍼
    void registerCustomClasses(JSValue global_obj);
};
