#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <chrono>
#include <sstream>
#include <numeric>

#include "../../../Getter/Resolver/ExternalLib_json.hpp"

#include "AnalysisResponse.h"
#include "../model/Detection.h"
#include "../hooks/HookEvent.h"
#include "../hooks/HookType.h"
#include "metadata/RouteHint.h"
#include "../chain/AttackChain.h"
#include "../chain/ChainStep.h"
#include "../core/ChainTrackerManager.h"
#include "../core/DynamicStringTracker.h"
#include "builders/DetectionBuilder.h"
#include "builders/SummaryGenerator.h"
#include "builders/EventProcessor.h"
#include "filters/EventFilter.h"
#include "processors/CryptoChainProcessor.h"
#include "../parser/js/UrlCollector.h"  // 🔥 NEW
#include "../builtin/helpers/UrlComparator.h"  // 🔥 NEW

// Forward declaration for JSAnalyzerContext to access managers
struct JSAnalyzerContext;

class ResponseGenerator {
public:
    // Crypto operation grouping structure
    struct CryptoGroup {
        std::vector<HookEvent> events;
        bool hasEval = false;
        long long startTime = 0;
        long long endTime = 0;
        std::string description;
    };

private:
    // 새로운 Helper 클래스들
    std::unique_ptr<DetectionBuilder> detectionBuilder_;
    std::unique_ptr<SummaryGenerator> summaryGenerator_;
    std::unique_ptr<EventProcessor> eventProcessor_;
    
    int detectionOrderCounter = 0;  // Detection 순서 추적용 카운터
    std::vector<std::string> domExtractedUrls_;  // DOM 조작에서 발견된 URL들
    std::string scanTargetUrl_;  // 🔥 NEW: 검사 대상 URL
    
    void addDynamicAnalysisResults(AnalysisResponse& response, const std::vector<htmljs_scanner::Detection>& staticFindings, JSAnalyzerContext* a_ctx, int& orderCounter);
    void collectDomUrls(const std::vector<HookEvent>& domEvents);  // DOM에서 URL 수집
    void addRouteHints(AnalysisResponse& response, const std::vector<htmljs_scanner::Detection>& staticFindings);
    
    // 🔥 NEW: 외부 통신 분석
    nlohmann::json analyzeExternalCommunications(const std::vector<UrlMetadata>& urlMetadataList);
    void addExternalCommunicationDetection(AnalysisResponse& response, 
                                          const std::vector<UrlMetadata>& urlMetadataList,
                                          int& orderCounter);
    
    // ⚠️ REMOVED: generateAttackChainSummary - using SummaryGenerator::generateAttackChainSummary
    // Sub-methods for addDynamicAnalysisResults
    void processStaticFindings(htmljs_scanner::Detection& detection, const std::vector<htmljs_scanner::Detection>& staticFindings, int& maxSeverity);
    void processAttackChains(htmljs_scanner::Detection& detection, const std::vector<AttackChain>& completedChains, int& maxSeverity);
    void processHookEvents(htmljs_scanner::Detection& detection, const std::vector<HookEvent>& relevantHookEvents, const std::vector<HookEvent>& allHookEvents, int& maxSeverity);
    void processStringEvents(htmljs_scanner::Detection& detection, const std::vector<DynamicStringTracker::SensitiveStringEvent>& stringEvents, int& maxSeverity);
    void processTaintData(htmljs_scanner::Detection& detection, AnalysisResponse& response, TaintTracker* taintTracker, int& maxSeverity);
    std::string buildCryptoChainString(const std::vector<std::string>& cryptoChain) const;
    
    // Crypto operation grouping helper functions
    std::vector<CryptoGroup> groupConsecutiveCryptoOperations(const std::vector<HookEvent>& allEvents) const;
    std::string generateUserFriendlySummary(const std::vector<CryptoGroup>& cryptoGroups, bool hasEval) const;
    void addCryptoGroupDetection(AnalysisResponse& response, const CryptoGroup& group, int groupIndex, TaintTracker* taintTracker, int& orderCounter);
    // ⚠️ REMOVED: generateFetchRequestSummary - using SummaryGenerator::generateFetchRequestSummary
    
    // Taint pattern grouping helper functions
    struct TaintGroup {
        std::string type;               // "String Construction", "Decoding", "Malicious Content" 등
        std::string description;        // 그룹 설명
        std::vector<int> taintIndices;  // 관련된 Taint 인덱스들
        std::string combinedValue;      // 합쳐진 최종 값
        int maxLevel;                   // 최대 위험도
        std::string threat;             // 위협 유형
    };
    std::vector<TaintGroup> groupTaintedValues(const std::vector<TaintedValue*>& taintedValues) const;
    std::string evaluateThreat(const std::string& value) const;
    void addTaintGroupsToDetection(htmljs_scanner::Detection& detection, const std::vector<TaintGroup>& groups, int& maxSeverity);

    std::string convertJsValueToString(const JsValue& val) const;
    std::string generateFetchSummary(const std::map<std::string, JsValue>& metadata) const;
    int calculateSeverity(const std::string& reason) const;

    // Helper methods for chain analysis
    std::string getDetailedChainType(const AttackChain& chain) const;
    std::string extractSideEffects(const ChainStep& step) const;
    std::string simplifyChainType(const std::string& chainType) const;
    std::string buildChainString(const AttackChain& chain) const;
    long long calculateDuration(const AttackChain& chain) const;
    std::string extractChainEffects(const AttackChain& chain) const;

    AnalysisResponse createFallbackErrorResponseObject(const std::string& taskId, const std::string& errorMessage) const;
    AnalysisResponse buildAnalysisResponse(const std::string& taskId, const std::vector<htmljs_scanner::Detection>& staticFindings,
                                           std::vector<std::string>& extractedUrls, long long executionTimeMs, JSAnalyzerContext* a_ctx);

public:
    std::string createFallbackErrorResponse(const std::string& taskId, const std::string& errorMessage) const;

    ResponseGenerator();
    ~ResponseGenerator();
    
    // 🔥 NEW: 검사 URL 설정
    void setScanTargetUrl(const std::string& url) {
        scanTargetUrl_ = url;
    }

    std::string generateAnalysisResponse(const std::string& taskId, const std::vector<htmljs_scanner::Detection>& staticFindings,
                                         std::vector<std::string>& extractedUrls, long long executionTimeMs, JSAnalyzerContext* a_ctx);
    AnalysisResponse generateAnalysisResponseObject(const std::string& taskId, const std::vector<htmljs_scanner::Detection>& staticFindings,
                                                    std::vector<std::string>& extractedUrls, long long executionTimeMs, JSAnalyzerContext* a_ctx);
};