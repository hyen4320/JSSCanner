#include "pch.h"
#include "ResponseGenerator.h"
#include "../core/JSAnalyzer.h" // For JSAnalyzerContext definition
#include "../model/Detection.h"
#include "../model/JsValueVariant.h"
#include "../hooks/HookEvent.h"
#include "../hooks/HookType.h"
#include "builders/DetectionBuilder.h"
#include "builders/SummaryGenerator.h"
#include "builders/EventProcessor.h"
#include "constants/AnalysisConstants.h"
// 생성자
ResponseGenerator::ResponseGenerator() 
    : detectionBuilder_(std::make_unique<DetectionBuilder>()),
      summaryGenerator_(std::make_unique<SummaryGenerator>()),
      eventProcessor_(std::make_unique<EventProcessor>()) {
}

// 소멸자
ResponseGenerator::~ResponseGenerator() = default;

// Helper function to add detection with order tracking
void addDetectionWithOrder(AnalysisResponse& response, htmljs_scanner::Detection& detection, int& orderCounter) {
    detection.detectionOrder = ++orderCounter;
    response.addDetection(detection);
}

// Helper to convert JsValue to string for general use in reporting
std::string ResponseGenerator::convertJsValueToString(const JsValue& val) const {
    return JsValueToString(val);
}

// Generate human-readable summary for FETCH_REQUEST events
std::string ResponseGenerator::generateFetchSummary(const std::map<std::string, JsValue>& metadata) const {
    std::string method = "GET";
    std::string url = "(unknown)";
    std::string keywords;
    
    // Extract method
    auto methodIt = metadata.find("method");
    if (methodIt != metadata.end()) {
        if (std::holds_alternative<std::string>(methodIt->second.get())) {
            method = std::get<std::string>(methodIt->second.get());
        }
    }
    
    // Extract URL
    auto urlIt = metadata.find("url");
    if (urlIt != metadata.end()) {
        if (std::holds_alternative<std::string>(urlIt->second.get())) {
            url = std::get<std::string>(urlIt->second.get());
        }
    }
    
    // Extract keywords
    auto keywordsIt = metadata.find("keywords");
    if (keywordsIt != metadata.end()) {
        if (std::holds_alternative<std::string>(keywordsIt->second.get())) {
            keywords = std::get<std::string>(keywordsIt->second.get());
        }
    }
    
    // Build summary
    std::stringstream summary;
    summary << method << " " << url;
    
    if (!keywords.empty()) {
        summary << " - Transmitting sensitive data (" << keywords << ")";
    } else if (url.find("http://") == 0 || url.find("https://") == 0 || url.find("//") == 0) {
        summary << " - External resource loading";
    } else {
        summary << " - HTTP request";
    }
    
    return summary.str();
}

int ResponseGenerator::calculateSeverity(const std::string& reason) const {
    if (reason.find("eval") != std::string::npos) return 6;
    if (reason.find("activex") != std::string::npos) return 6;
    if (reason.find("wscript") != std::string::npos) return 6;
    if (reason.find("document_write") != std::string::npos) return 4;
    if (reason.find("window_location_redirect") != std::string::npos) return 5;
    if (reason.find("url") != std::string::npos) return 5;
    return 3; // Default
}

std::string ResponseGenerator::getDetailedChainType(const AttackChain& chain) const {
    std::string baseType = chain.getChainType();
    
    for (const auto& step : chain.getSteps()) {
        // Assuming JsValueToString can handle null/undefined and returns empty string or specific literal
        std::string output = JsValueToString(step.output.value);
        std::transform(output.begin(), output.end(), output.begin(), ::tolower);
                
        if (output.find("<iframe") != std::string::npos) {
            return baseType + "_IFRAME_INJECTION";
        } else if (output.find("<script") != std::string::npos) {
            return baseType + "_SCRIPT_INJECTION";
        } else if (output.find("document.write") != std::string::npos) {
            return baseType + "_DOM_MANIPULATION";
        } else if (output.find("activexobject") != std::string::npos) {
            return baseType + "_ACTIVEX_ABUSE";
        } else if (output.find("location") != std::string::npos && output.find("=") != std::string::npos) {
            return baseType + "_REDIRECT_ATTACK";
        }
    }
        
    return baseType;
}

std::string ResponseGenerator::extractSideEffects(const ChainStep& step) const {
    std::set<std::string> effects;
        
    // Assuming JsValueToString can handle null/undefined and returns empty string or specific literal
    std::string output = JsValueToString(step.output.value);
    std::transform(output.begin(), output.end(), output.begin(), ::tolower);
        
    if (output.find("document.write") != std::string::npos || output.find("innerhtml") != std::string::npos) {
        effects.insert("DOM_MODIFIED");
    }
        
    if (output.find("http://") != std::string::npos || output.find("https://") != std::string::npos) {
        effects.insert("EXTERNAL_RESOURCE_LOADED");
    }
        
    if (output.find("<iframe") != std::string::npos) {
        effects.insert("IFRAME_INJECTED");
    }
        
    if (output.find("<script") != std::string::npos) {
        effects.insert("SCRIPT_INJECTED");
    }
        
    if (output.find("location") != std::string::npos && (output.find("=") != std::string::npos || output.find("replace") != std::string::npos)) {
        effects.insert("REDIRECT_ATTEMPTED");
    }
        
    if (output.find("activexobject") != std::string::npos) {
        effects.insert("ACTIVEX_INSTANTIATED");
    }
        
    std::string result_effects;
    for (const std::string& effect : effects) {
        if (!result_effects.empty()) result_effects += ", ";
        result_effects += effect;
    }
    return result_effects;
}

std::string ResponseGenerator::simplifyChainType(const std::string& chainType) const {
    if (chainType.empty()) return "unknown";

    std::string simplified = chainType;
    RE2::GlobalReplace(&simplified, "Chain_", "");
    RE2::GlobalReplace(&simplified, "_DOM_MANIPULATION", "");
    std::replace(simplified.begin(), simplified.end(), '_', '-');
    std::transform(simplified.begin(), simplified.end(), simplified.begin(), ::tolower);
    return simplified;
}

std::string ResponseGenerator::buildChainString(const AttackChain& chain) const {
    std::vector<std::string> operations;
    std::map<std::string, int> operationCount;
        
    std::string prevOp;
    int count = 0;
        
    for (const auto& step : chain.getSteps()) {
        std::string op = step.functionName;
            
        if (op == prevOp) {
            count++;
        } else {
            if (!prevOp.empty()) {
                if (count > AnalysisConstants::MIN_COMPRESS_COUNT) {
                    operations.push_back(prevOp + " (×" + std::to_string(count) + ")");
                } else {
                    for (int i = 0; i < count; i++) {
                        operations.push_back(prevOp);
                    }
                }
            }
            prevOp = op;
            count = 1;
        }
    }

    if (!prevOp.empty()) {
        if (count > AnalysisConstants::MIN_COMPRESS_COUNT) {
            operations.push_back(prevOp + " (×" + std::to_string(count) + ")");
        } else {
            for (int i = 0; i < count; i++) {
                operations.push_back(prevOp);
            }
        }
    }

    // 🔥 단계 제한 표시
    if (operations.size() > AnalysisConstants::MAX_DISPLAY_STEPS) {
        std::vector<std::string> limited(operations.begin(), operations.begin() + AnalysisConstants::MAX_DISPLAY_STEPS);
        limited.push_back("(+" + std::to_string(operations.size() - AnalysisConstants::MAX_DISPLAY_STEPS) + " more steps)");
        return std::accumulate(limited.begin(), limited.end(), std::string(),
                               [](const std::string& a, const std::string& b) -> std::string {
                                   return a.empty() ? b : a + " -> " + b;
                               });
    }

    return std::accumulate(operations.begin(), operations.end(), std::string(),
                           [](const std::string& a, const std::string& b) -> std::string {
                               return a.empty() ? b : a + " -> " + b;
                           });
}

long long ResponseGenerator::calculateDuration(const AttackChain& chain) const {
    if (chain.getSteps().empty()) {
        return 0;
    }
        
    long long start = chain.getSteps().front().timestamp;
    long long end = chain.getSteps().back().timestamp;
    return end - start;
}

std::string ResponseGenerator::extractChainEffects(const AttackChain& chain) const {
    std::set<std::string> effects;
        
    for (const auto& step : chain.getSteps()) {
        std::string stepEffects = extractSideEffects(step);
        if (!stepEffects.empty()) {
            std::stringstream ss(stepEffects);
            std::string effect;
            while (std::getline(ss, effect, ',')) {
                effects.insert(effect);
            }
        }
    }
        
    std::string result_effects;
    for (const std::string& effect : effects) {
        if (!result_effects.empty()) result_effects += ", ";
        result_effects += effect;
    }
    return result_effects;
}

std::string ResponseGenerator::createFallbackErrorResponse(const std::string& taskId, const std::string& errorMessage) const {
    // Get current date for rules version
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm* now_tm = std::localtime(&now_c);

    std::stringstream date_ss;
    date_ss << std::put_time(now_tm, "%Y-%m-%d");
    std::string rules_date = date_ss.str();

    nlohmann::json j;
    j["TaskId"] = taskId;
    j["Status"] = "ERROR";
    j["ExtractedFile"] = nlohmann::json::array();
    j["ExtractedURL"] = nlohmann::json::array();
    j["Detection"] = nlohmann::json::array();
    j["RouteHints"] = nlohmann::json::array();
    j["timings"] = {{"TookMs", 0}};
    j["Version"] = {{"Scanner", "1.0.0"}, {"Rules", rules_date}};
    j["Errors"] = nlohmann::json::array({"JSON 생성 실패: " + errorMessage});

    return j.dump(4); // Pretty print with 4 spaces
}

AnalysisResponse ResponseGenerator::createFallbackErrorResponseObject(const std::string& taskId, const std::string& errorMessage) const {
    AnalysisResponse response(taskId);
    std::string localizedError = "JSON 생성 실패: " + errorMessage;
    response.addError(localizedError);
    response.setExtractedFiles({});
    response.setExtractedUrls({});
    response.setTimings({ Timing(0) });
    return response;
}

AnalysisResponse ResponseGenerator::buildAnalysisResponse(const std::string& taskId, const std::vector<htmljs_scanner::Detection>& staticFindings,
                                                          std::vector<std::string>& extractedUrls, long long executionTimeMs, JSAnalyzerContext* a_ctx) {
    try {
        domExtractedUrls_.clear();  // DOM에서 발견된 URL 초기화
        
        AnalysisResponse response(taskId);
        int orderCounter = 0;  // 순서 카운터 초기화
        addDynamicAnalysisResults(response, staticFindings, a_ctx, orderCounter);
        
        // DOM에서 발견된 URL을 ExtractedUrls에 추가
        if (!domExtractedUrls_.empty()) {
            core::Log_Info("%sAdding %s",logMsg,  std::to_string(domExtractedUrls_.size()) + 
                        " URLs from DOM manipulation to ExtractedUrls");
            extractedUrls.insert(extractedUrls.end(), 
                               domExtractedUrls_.begin(), 
                               domExtractedUrls_.end());
        }
        
        // 🔥 NEW: 외부 통신 분석 (기존 포맷에 맞춤)
        if (a_ctx && a_ctx->urlCollector && !scanTargetUrl_.empty()) {
            const std::vector<UrlMetadata>& urlMetadataList = 
                a_ctx->urlCollector->getUrlMetadataList();
            
            if (!urlMetadataList.empty()) {
                addExternalCommunicationDetection(response, urlMetadataList, orderCounter);
            }
        }
        
        response.setExtractedUrls(extractedUrls);
        addRouteHints(response, staticFindings);
        response.setTimings({ Timing(executionTimeMs) });
        return response;
    } catch (const std::exception& e) {
        AnalysisResponse fallback = createFallbackErrorResponseObject(taskId, e.what());
        fallback.setExtractedUrls(extractedUrls);
        fallback.setTimings({ Timing(executionTimeMs) });
        return fallback;
    }
}

void ResponseGenerator::processStaticFindings(htmljs_scanner::Detection& detection, const std::vector<htmljs_scanner::Detection>& staticFindings, int& maxSeverity) {
    if (staticFindings.empty()) return;
    
    std::map<std::string, int> reasonCountMap;
    std::set<std::string> addedSnippets;
    
    for (const auto& finding : staticFindings) {
        std::string reason = finding.reason;
        std::string snippet = finding.snippet;
        
        // window_location URL 추출
        if (reason.find("window_location") != std::string::npos) {
            std::string content = snippet;
            size_t arrow_pos = content.find("window.location -> ");
            if (arrow_pos != std::string::npos) {
                content = content.substr(arrow_pos + 19);
            }
            
            RE2 url_pattern(R"((?i)(https?://[^\s'"]+))");
            std::string url_match;
            if (RE2::PartialMatch(content, url_pattern, &url_match)) {
                snippet = "Redirects to '" + url_match + "'";
            } else {
                snippet = "Redirects using window.location";
            }
        }
        
        if (addedSnippets.count(snippet)) continue;
        
        reasonCountMap[reason]++;
        std::string featureKey = reason + "_" + std::to_string(reasonCountMap[reason]);
        detection.addFeature(featureKey, JsValue(snippet));
        addedSnippets.insert(snippet);
        
        int severity = calculateSeverity(reason);
        maxSeverity = std::max(maxSeverity, severity);
    }
}

void ResponseGenerator::processAttackChains(htmljs_scanner::Detection& detection, const std::vector<AttackChain>& completedChains, int& maxSeverity) {
    if (completedChains.empty()) return;
    
    std::map<std::string, JsValue> chainSummary;
    chainSummary["total_chains"] = static_cast<double>(completedChains.size());
    
    std::vector<JsValue> chainsArray;
    int highestChainSeverity = 0;
    
    for (size_t i = 0; i < completedChains.size(); ++i) {
        const AttackChain& chain = completedChains[i];
        
        std::map<std::string, JsValue> chainObj;
        chainObj["id"] = static_cast<double>(i + 1);
        chainObj["type"] = JsValue(simplifyChainType(chain.getChainType()));
        chainObj["severity"] = static_cast<double>(chain.getFinalSeverity());
        chainObj["steps"] = static_cast<double>(chain.getSteps().size());
        chainObj["flow"] = JsValue(buildChainString(chain));
        chainObj["duration_ms"] = static_cast<double>(calculateDuration(chain));
        chainObj["verified"] = chain.verifyCausality();
        
        std::string effects = extractChainEffects(chain);
        if (!effects.empty()) {
            chainObj["impact"] = JsValue(effects);
        }
        
        chainsArray.push_back(JsValue(chainObj));
        
        highestChainSeverity = std::max(highestChainSeverity, chain.getFinalSeverity());
    }
    
    chainSummary["chains"] = JsValue(chainsArray);
    detection.addFeature(HookTypeToString(HookType::ATTACK_CHAINS), JsValue(chainSummary));
    
    // 사용자 친화적인 요약 추가 - SummaryGenerator 사용
    std::string attackSummary = summaryGenerator_->generateAttackChainSummary(completedChains);
    detection.addFeature(HookTypeToString(HookType::SUMMARY), JsValue(attackSummary));
    
    maxSeverity = std::max(maxSeverity, highestChainSeverity);
}

std::string ResponseGenerator::buildCryptoChainString(const std::vector<std::string>& cryptoChain) const {
    return CryptoChainProcessor::buildCryptoChainString(cryptoChain);
}

std::string ResponseGenerator::generateUserFriendlySummary(const std::vector<CryptoGroup>& cryptoGroups, bool hasEval) const {
    if (cryptoGroups.empty()) {
        return "No obfuscation detected";
    }
    
    // 전체 난독화 시도 횟수 계산
    int totalObfuscations = 0;
    int maxChainLength = 0;
    std::set<std::string> uniqueTechniques;
    std::vector<std::string> chainExamples;
    
    for (const auto& group : cryptoGroups) {
        int chainLength = 0;
        std::vector<std::string> chainSteps;
        
        for (const auto& event : group.events) {
            if (event.type == HookType::CRYPTO_OPERATION || 
                (event.type == HookType::FUNCTION_CALL && event.name != "eval")) {
                chainLength++;
                uniqueTechniques.insert(event.name);
                chainSteps.push_back(event.name);
            }
        }
        
        // 첫 3개 체인의 예시 수집
        if (chainExamples.size() < 3 && !chainSteps.empty()) {
            std::string example = "";
            for (size_t i = 0; i < std::min(size_t(3), chainSteps.size()); ++i) {
                if (i > 0) example += " → ";
                example += chainSteps[i];
            }
            if (chainSteps.size() > 3) example += " → ...";
            if (group.hasEval) example += " → eval()";
            chainExamples.push_back(example);
        }
        
        totalObfuscations += chainLength;
        maxChainLength = std::max(maxChainLength, chainLength);
    }
    
    // 위험도 레벨 결정
    std::string threatLevel = CryptoChainProcessor::determineThreatLevel(maxChainLength, hasEval);
    // HIGH 레벨에 공백 추가 (포맷팅)
    if (threatLevel == "HIGH") {
        threatLevel = "  HIGH";
    }
    
    // 요약 메시지 생성
    std::ostringstream summary;
    summary << threatLevel << " - ";
    summary << "Detected " << cryptoGroups.size() << " obfuscation chain"
            << (cryptoGroups.size() > 1 ? "s" : "");
    summary << " using " << totalObfuscations << " encoding/decoding operation"
            << (totalObfuscations > 1 ? "s" : "");
    // 🔥 총 작업이 여러 그룹에서 제한 이상이면 표시
    if (totalObfuscations >= cryptoGroups.size() * AnalysisConstants::MAX_CRYPTO_CHAIN_SIZE) {
        summary << " (groups capped at " << AnalysisConstants::MAX_CRYPTO_CHAIN_SIZE << " each)";
    }
    summary << " across " << uniqueTechniques.size() << " different technique"
            << (uniqueTechniques.size() > 1 ? "s" : "");
    
    // 사용된 기술 나열
    if (!uniqueTechniques.empty()) {
        summary << " [Techniques: ";
        int techCount = 0;
        for (const auto& tech : uniqueTechniques) {
            if (techCount > 0) summary << ", ";
            summary << tech;
            if (++techCount >= 5) break; // 최대 5개
        }
        if (uniqueTechniques.size() > 5) {
            summary << ", +" << (uniqueTechniques.size() - 5) << " more";
        }
        summary << "]";
    }
    
    if (hasEval) {
        summary << ". Leads to DYNAMIC CODE EXECUTION via eval()";
    }
    
    // 가장 긴 체인 정보 추가
    if (maxChainLength >= 10) {
        summary << ". Longest chain: " << maxChainLength << " layers";
        // 🔥 제한 표시
        if (maxChainLength >= AnalysisConstants::MAX_CRYPTO_CHAIN_SIZE) {
            summary << " (capped at " << AnalysisConstants::MAX_CRYPTO_CHAIN_SIZE << ")";
        }
    }
    
    // 체인 예시 추가
    if (!chainExamples.empty()) {
        summary << ". Examples: ";
        for (size_t i = 0; i < chainExamples.size(); ++i) {
            if (i > 0) summary << " | ";
            summary << "[" << (i + 1) << "] " << chainExamples[i];
        }
    }
    
    return summary.str();
}

// ⚠️ REMOVED: generateAttackChainSummary() - now using SummaryGenerator::generateAttackChainSummary()

void ResponseGenerator::processHookEvents(htmljs_scanner::Detection& detection, const std::vector<HookEvent>& relevantHookEvents, const std::vector<HookEvent>& allHookEvents, int& maxSeverity) {
    std::map<std::string, int> typeCountMap;
    std::set<std::string> addedFeatureValues;
    std::vector<std::string> cryptoChain;
    
    // 🆕 간접 호출 패턴 감지
    std::vector<std::string> indirectCalls;
    int indirectCallCount = 0;
    
    // 🔥 먼저 allHookEvents에서 모든 CRYPTO_OPERATION 수집
    auto cryptoEvents = EventFilter::getCryptoOperations(allHookEvents);
    cryptoChain = CryptoChainProcessor::extractCryptoChain(allHookEvents);
    maxSeverity = std::max(maxSeverity, EventFilter::getMaxSeverity(cryptoEvents));

    // 🆕 간접 호출 감지 (window["eval"] 같은 패턴)
    auto indirectAccessEvents = EventFilter::getIndirectPropertyAccess(allHookEvents);
    for (const auto& event : indirectAccessEvents) {
        indirectCallCount++;

        // property 이름 추출
        auto propIt = event.metadata.find("property");
        if (propIt != event.metadata.end()) {
            std::string propName = convertJsValueToString(propIt->second);
            indirectCalls.push_back("window['" + propName + "']");
        }
    }
    maxSeverity = std::max(maxSeverity, EventFilter::getMaxSeverity(indirectAccessEvents));
    
    // 🆕 간접 호출 보고서에 추가
    if (!indirectCalls.empty()) {
        std::string indirectCallSummary = "Detected " + std::to_string(indirectCallCount) + 
                                         " indirect property access(es): " + 
                                         std::accumulate(indirectCalls.begin(), indirectCalls.end(), std::string(),
                                             [](const std::string& a, const std::string& b) {
                                                 return a.empty() ? b : a + ", " + b;
                                             });
        
        detection.addFeature(HookTypeToString(HookType::INDIRECT_ACCESS_SUMMARY), JsValue(indirectCallSummary));
        detection.addFeature(HookTypeToString(HookType::INDIRECT_ACCESS_COUNT), JsValue(static_cast<double>(indirectCallCount)));
        
        // 각 간접 호출을 개별적으로 기록
        for (size_t i = 0; i < indirectCalls.size(); ++i) {
            detection.addFeature(HookTypeToString(HookType::INDIRECT_ACCESS_PREFIX) + std::to_string(i + 1), JsValue(indirectCalls[i]));
        }
    }
    
    // 이제 relevantHookEvents로 나머지 이벤트 처리
    for (const auto& event : relevantHookEvents) {
        std::string hookType = HookTypeToString(event.type);
        
        // CRYPTO_OPERATION은 이미 처리했으므로 스킵
        if (event.type == HookType::CRYPTO_OPERATION) {
            continue;
        }
        
        if (event.type == HookType::FETCH_REQUEST && !event.metadata.empty()) {
            typeCountMap[hookType]++;
            std::string featureKey = hookType + "_" + std::to_string(typeCountMap[hookType]);
            detection.addFeature(featureKey, JsValue(event.metadata));
            maxSeverity = std::max(maxSeverity, event.severity);
            continue;
        }
        
        std::stringstream featureValueBuilder;
        featureValueBuilder << event.name;
        
        if (!event.args.empty()) {
            featureValueBuilder << "(";
            for (size_t i = 0; i < std::min(event.args.size(), size_t(3)); ++i) {
                if (i > 0) featureValueBuilder << ", ";
                std::string argStr = convertJsValueToString(event.args[i]);
                if (argStr.length() > 50) argStr = argStr.substr(0, 50) + "...";
                featureValueBuilder << argStr;
            }
            if (event.args.size() > 3) featureValueBuilder << ", ...";
            featureValueBuilder << ")";
        }
        
        if (!std::holds_alternative<std::monostate>(event.result.get())) {
            std::string resultStr = convertJsValueToString(event.result);
            if (resultStr.length() > 50) resultStr = resultStr.substr(0, 50) + "...";
            featureValueBuilder << " -> " << resultStr;
        }
        
        std::string finalValue = featureValueBuilder.str();
        RE2::GlobalReplace(&finalValue, "\r\n|\r|\n", " ");
        RE2::GlobalReplace(&finalValue, "\\s+", " ");
        
        if (addedFeatureValues.count(finalValue)) continue;
        
        typeCountMap[hookType]++;
        std::string featureKey = hookType + "_" + std::to_string(typeCountMap[hookType]);
        detection.addFeature(featureKey, JsValue(finalValue));
        addedFeatureValues.insert(finalValue);
        maxSeverity = std::max(maxSeverity, event.severity);
    }
    
    // CRYPTO_OPERATION 체인 처리
    if (!cryptoChain.empty()) {
        std::string chainStr = buildCryptoChainString(cryptoChain);
        detection.addFeature(HookTypeToString(HookType::CRYPTO_OPERATION_PREFIX) + "1", JsValue(chainStr));
        
        // eval 호출 확인
        bool hasEval = EventFilter::hasEvalCall(allHookEvents);
        
        if (hasEval) {
            detection.addFeature(HookTypeToString(HookType::FUNCTION_CALL_PREFIX) + "1", JsValue("eval(deobfuscated_code)"));
        }
    }
}

void ResponseGenerator::processStringEvents(htmljs_scanner::Detection& detection, const std::vector<DynamicStringTracker::SensitiveStringEvent>& stringEvents, int& maxSeverity) {
    if (stringEvents.empty()) return;
    
    int stringEventCount = 0;
    for (const auto& event : stringEvents) {
        stringEventCount++;
        std::string featureKey = HookTypeToString(HookType::STRING_TRACKING_PREFIX) + std::to_string(stringEventCount);
        std::string featureValue = event.type + ": " + event.varName + "=\"" + event.value + "\" (" + event.description + ")";
        detection.addFeature(featureKey, JsValue(featureValue));
        
        
        if (event.type == "indirect_call") {
            maxSeverity = std::max(maxSeverity, 8);
        } else if (event.type == "variable_assignment") {
            maxSeverity = std::max(maxSeverity, 7);
        } else if (event.type == "url_in_variable") {
            maxSeverity = std::max(maxSeverity, 6);
        }
    }
    detection.addFeature(HookTypeToString(HookType::STRING_TRACKING_COUNT), JsValue(static_cast<double>(stringEvents.size())));
}

void ResponseGenerator::processTaintData(htmljs_scanner::Detection& detection, AnalysisResponse& response, TaintTracker* taintTracker, int& maxSeverity) {
    if (!taintTracker) return;
    
    core::Log_Info("%sCollecting TaintTracker data...", logMsg.c_str());
    std::vector<TaintedValue*> taintedValues = taintTracker->getAllTaintedValues();
    core::Log_Info("%sFound %zu tainted values", logMsg.c_str(), taintedValues.size());
    
    if (taintedValues.empty()) {
        // Taint 통계만 수집
        auto taintStats = taintTracker->getStatistics();
        core::Log_Info("%sTaintTracker statistics: %zu items", logMsg.c_str(), taintStats.size());
        for (const auto& [key, value] : taintStats) {
            response.addTaintStatistic(key, value);
            core::Log_Debug("%s  Taint stat: %s = %s", logMsg.c_str(), key.c_str(), JsValueToString(value).c_str());
        }
        return;
    }
    
    // 🆕 Taint 그룹화 수행
    std::vector<TaintGroup> taintGroups = groupTaintedValues(taintedValues);
    core::Log_Info("%sGrouped into %zu meaningful patterns", logMsg.c_str(), taintGroups.size());
    
    // 그룹화된 패턴을 Detection에 추가
    addTaintGroupsToDetection(detection, taintGroups, maxSeverity);
    
    // 개별 Taint도 여전히 response에 추가 (상세 정보용)
    int taintCount = 0;
    for (auto* taintedValue : taintedValues) {
        if (taintedValue && taintedValue->getTaintLevel() >= 3) {
            taintCount++;
            response.addTaintedValue(*taintedValue);
            maxSeverity = std::max<int>(maxSeverity, taintedValue->getTaintLevel());
        }
    }
    
    // Taint 통계 수집
    auto taintStats = taintTracker->getStatistics();
    core::Log_Debug("TaintTracker statistics: %zu items", taintStats.size());
    for (const auto& [key, value] : taintStats) {
        response.addTaintStatistic(key, value);
        core::Log_Debug("  Taint stat: %s = %s", key.c_str(), JsValueToString(value).c_str());
    }
}

void ResponseGenerator::addDynamicAnalysisResults(AnalysisResponse& response, const std::vector<htmljs_scanner::Detection>& staticFindings, JSAnalyzerContext* a_ctx, int& orderCounter) {
    core::Log_Warn("=== addDynamicAnalysisResults CALLED ===");
    core::Log_Debug("Current Detections count: %zu", response.getDetections().size());
    
    if (!a_ctx || !a_ctx->dynamicAnalyzer || !a_ctx->chainTrackerManager || !a_ctx->dynamicStringTracker) {
        core::Log_Warn("=== addDynamicAnalysisResults EARLY RETURN (null context) ===");
        return;
    }

    // 데이터 수집
    const std::vector<HookEvent>& allHookEvents = a_ctx->dynamicAnalyzer->getHookEvents();
    std::vector<HookEvent> relevantHookEvents;
    relevantHookEvents.reserve(allHookEvents.size());
    for (const auto& event : allHookEvents) {
        if (event.getSeverity() >= AnalysisConstants::MIN_RELEVANT_SEVERITY ||
            event.type == HookType::DATA_EXFILTRATION ||
            event.type == HookType::FETCH_REQUEST) {
            relevantHookEvents.push_back(event);
        }
    }

    const std::vector<AttackChain>& completedChains = a_ctx->chainTrackerManager->getChainDetector()->getCompletedChains();
    const std::vector<DynamicStringTracker::SensitiveStringEvent>& stringEvents = a_ctx->dynamicStringTracker->getDetectedEvents();

    core::Log_Info("Dynamic analysis: staticFindings=%zu, events=%zu, chains=%zu, strings=%zu",
                   staticFindings.size(), relevantHookEvents.size(), completedChains.size(), stringEvents.size());

    if (staticFindings.empty() && relevantHookEvents.empty() && completedChains.empty() && stringEvents.empty()) {
        core::Log_Warn("=== addDynamicAnalysisResults EARLY RETURN (no data) ===");
        return;
    }

    // 🔥 NEW: Crypto 작업을 독립적인 그룹으로 분리
    std::vector<CryptoGroup> cryptoGroups = groupConsecutiveCryptoOperations(allHookEvents);
    core::Log_Info("Found %zu independent obfuscation chains", cryptoGroups.size());
    
    // 🔥 모든 Crypto 그룹을 하나의 통합 Detection으로 생성
    if (!cryptoGroups.empty()) {
        htmljs_scanner::Detection unifiedDetection;
        unifiedDetection.analysisCode = "DA";
        unifiedDetection.name = "JSScanner.OBFUSCATION_CHAINS";
        
        int maxSeverity = 0;
        bool hasEval = false;
        
        // 각 그룹을 개별 Feature로 추가
        for (size_t i = 0; i < cryptoGroups.size(); ++i) {
            const auto& group = cryptoGroups[i];

            // Crypto 체인 생성
            std::vector<std::string> cryptoChain;
            int arrayJoinCount = 0;
            for (const auto& event : group.events) {
                if (event.type == HookType::CRYPTO_OPERATION) {
                    cryptoChain.push_back(event.name);
                } else if (event.type == HookType::FUNCTION_CALL &&
                           AnalysisConstants::OBFUSCATION_FUNCTIONS.count(event.name) > 0 &&
                           event.name != "eval") {
                    cryptoChain.push_back(event.name);
                    if (event.name == "Array.join") {
                        arrayJoinCount++;
                    }
                }
            }

            // 🔥 Array.join만 있고 MIN_ARRAY_JOIN_COUNT 미만이면 스킵
            int nonArrayJoinCount = static_cast<int>(cryptoChain.size()) - arrayJoinCount;
            bool shouldSkip = (arrayJoinCount > 0 && arrayJoinCount < AnalysisConstants::MIN_ARRAY_JOIN_COUNT && nonArrayJoinCount == 0);

            if (!cryptoChain.empty() && !shouldSkip) {
                std::string chainStr = buildCryptoChainString(cryptoChain);
                std::string featureKey = HookTypeToString(HookType::CHAIN_PREFIX) + std::to_string(i + 1);
                
                if (group.hasEval) {
                    chainStr += " -> eval";
                    hasEval = true;
                    maxSeverity = std::max(maxSeverity, 10);
                } else {
                    maxSeverity = std::max(maxSeverity, 7);
                }
                
                unifiedDetection.addFeature(featureKey, JsValue(chainStr));
            }
        }
        
        // 전체 요약 정보
        unifiedDetection.addFeature(HookTypeToString(HookType::TOTAL_CHAINS), JsValue(static_cast<double>(cryptoGroups.size())));
        unifiedDetection.addFeature(HookTypeToString(HookType::HIGHEST_SEVERITY), JsValue(static_cast<double>(maxSeverity)));
        
        // 🎯 사용자 친화적인 요약 메시지 생성
        std::string userSummary = generateUserFriendlySummary(cryptoGroups, hasEval);
        unifiedDetection.addFeature(HookTypeToString(HookType::SUMMARY), JsValue(userSummary));
        
        if (hasEval) {
            unifiedDetection.addFeature(HookTypeToString(HookType::EVAL_DETECTED), JsValue("true"));
        }

        
        unifiedDetection.severity = maxSeverity;
        
        core::Log_Info("%sAdding unified obfuscation detection with %zu chains, severity %d", 
                       logMsg.c_str(), cryptoGroups.size(), maxSeverity);
        addDetectionWithOrder(response, unifiedDetection, orderCounter);
    }
    
    // 🔥 Taint는 전체 요약으로 한 번만 추가 (중복 방지)
    if (a_ctx->chainTrackerManager->getTaintTracker()) {
        TaintTracker* taintTracker = a_ctx->chainTrackerManager->getTaintTracker();
        std::vector<TaintedValue*> allTaints = taintTracker->getAllTaintedValues();
        
        core::Log_Info("%sProcessing %zu tainted values for global summary", logMsg.c_str(), allTaints.size());
        
        // 전체 Taint 통계만 추가
        for (auto* taint : allTaints) {
            if (taint && taint->getTaintLevel() >= 3) {
                response.addTaintedValue(*taint);
            }
        }
        
        // 통계 수집
        auto taintStats = taintTracker->getStatistics();
        for (const auto& [key, value] : taintStats) {
            response.addTaintStatistic(key, value);
        }
    }
    
    // Attack Chain이 있으면 별도 Detection 생성
    if (!completedChains.empty()) {
        htmljs_scanner::Detection chainDetection;
        chainDetection.analysisCode = "DA";
        chainDetection.name = "JSScanner.ATTACK_CHAIN";
        int chainSeverity = 0;
        
        processAttackChains(chainDetection, completedChains, chainSeverity);
        
        if (chainSeverity == 0) {
            chainSeverity = 7;
        }
        chainDetection.severity = chainSeverity;
        
        core::Log_Info("%sAdding Attack Chain detection with severity %d", logMsg.c_str(), chainSeverity);
        addDetectionWithOrder(response, chainDetection, orderCounter);
    }
    
    // 🔥 기타 중요 이벤트들은 Crypto 그룹에 이미 포함되어 있으므로
    // 별도 Detection 생성하지 않음 (중복 방지)
    // FETCH_REQUEST, DATA_EXFILTRATION, 간접 호출, DOM_MANIPULATION 등 특수 이벤트만 별도 처리
    
    core::Log_Info("%sChecking %zu relevant events for categorization", logMsg.c_str(), relevantHookEvents.size());
    
    // 🔥 이벤트 분류 (새로운 EventProcessor 사용)
    auto categorized = eventProcessor_->categorizeEvents(relevantHookEvents);
    
    core::Log_Info("%sEvent categorization complete:", logMsg.c_str());
    core::Log_Info("%s  - DOM Manipulation: %zu", logMsg.c_str(), categorized.domEvents.size());
    core::Log_Info("%s  - Location Change: %zu", logMsg.c_str(), categorized.locationEvents.size());
    core::Log_Info("%s  - Address Manipulation: %zu", logMsg.c_str(), categorized.addrEvents.size());
    core::Log_Info("%s  - Environment Detection: %zu", logMsg.c_str(), categorized.environmentEvents.size());
    core::Log_Info("%s  - Critical Events: %zu", logMsg.c_str(), categorized.criticalEvents.size());
    
    // 🔥 DOM_MANIPULATION Detection 생성 (새로운 DetectionBuilder 사용)
    if (categorized.hasDom()) {
        collectDomUrls(categorized.domEvents);
        std::string summary = summaryGenerator_->generateDomManipulationSummary(categorized.domEvents);
        htmljs_scanner::Detection domDetection = detectionBuilder_->buildDomManipulationDetection(
            categorized.domEvents, summary);
        core::Log_Info("%sAdding DOM_MANIPULATION detection with severity %d", logMsg.c_str(), domDetection.severity);
        response.addDetection(domDetection);
    }
    
    // 🔥 LOCATION_CHANGE Detection 생성 (새로운 Builder 사용)
    if (categorized.hasLocation()) {
        std::string summary = summaryGenerator_->generateLocationChangeSummary(categorized.locationEvents);
        htmljs_scanner::Detection locationDetection = detectionBuilder_->buildLocationChangeDetection(
            categorized.locationEvents, summary);
        core::Log_Info("%sAdding LOCATION_CHANGE detection with severity %d", logMsg.c_str(), locationDetection.severity);
        response.addDetection(locationDetection);
    }
    
    // 🔥 ADDR_MANIPULATION Detection 생성 (새로운 Builder 사용)
    if (categorized.hasAddr()) {
        std::string summary = summaryGenerator_->generateAddrManipulationSummary(categorized.addrEvents);
        htmljs_scanner::Detection addrDetection = detectionBuilder_->buildAddrManipulationDetection(
            categorized.addrEvents, summary);
        core::Log_Info("%sAdding ADDR_MANIPULATION detection with severity %d", logMsg.c_str(), addrDetection.severity);
        response.addDetection(addrDetection);
    }
    
    // 🔥 ENVIRONMENT_DETECTION Detection 생성 (새로운 Builder 사용)
    if (categorized.hasEnvironment()) {
        std::string summary = summaryGenerator_->generateEnvironmentSummary(categorized.environmentEvents);
        htmljs_scanner::Detection envDetection = detectionBuilder_->buildEnvironmentDetection(
            categorized.environmentEvents, summary);
        core::Log_Info("%sAdding ENVIRONMENT_DETECTION detection with severity %d", logMsg.c_str(), envDetection.severity);
        response.addDetection(envDetection);
    }
    
    core::Log_Info("%sTotal critical events: %zu", logMsg.c_str(), categorized.criticalEvents.size());
    
    // 🔥🔥🔥 중요: staticFindings를 실제 Detection으로 변환
    if (!staticFindings.empty()) {
        core::Log_Info("%sProcessing %zu static findings as detections", logMsg.c_str(), staticFindings.size());
        
        // 🔥 NEW: script_error는 제외 (실행 환경 문제이지 악성 행위가 아님)
        std::vector<htmljs_scanner::Detection> filteredFindings;
        for (const auto& finding : staticFindings) {
            if (finding.reason != "script_error" && 
                finding.reason != "script_complexity_warning" &&
                finding.reason != "script_complexity_error") {
                filteredFindings.push_back(finding);
            } else {
                core::Log_Info("%sSkipping %s detection (not malicious)", logMsg.c_str(), finding.reason.c_str());
            }
        }
        
        if (filteredFindings.empty()) {
            core::Log_Info("%sNo malicious static findings to report after filtering", logMsg.c_str());
        } else {
            core::Log_Info("%sReporting %zu malicious static findings", logMsg.c_str(), filteredFindings.size());
        }
        
        // 같은 타입의 findings를 그룹화
        std::map<std::string, std::vector<htmljs_scanner::Detection>> groupedFindings;
        for (const auto& finding : filteredFindings) {
            groupedFindings[finding.reason].push_back(finding);
        }
        
        // 각 그룹을 하나의 Detection으로 생성
        for (const auto& [reason, findings] : groupedFindings) {
            htmljs_scanner::Detection det;
            det.analysisCode = "DA";
            
            // 🔥 HookType을 사용하여 reason을 Detection 이름과 severity로 변환
            auto [detectionType, severity] = ReasonToDetectionType(reason);
            det.name = "JSScanner." + HookTypeToString(detectionType);
            det.severity = severity;
            
            // Unknown reason 경고
            if (detectionType == HookType::STATIC_FINDING && reason != "static_finding") {
                core::Log_Warn("Unknown static finding reason: %s", reason.c_str());
            }
            
            // 🎯 상세한 패턴 분석
            std::set<std::string> detectedPatterns;
            std::set<std::string> variableNames;
            std::string firstSnippet;
            int totalLength = 0;
            
            for (size_t i = 0; i < findings.size(); ++i) {
                std::string featureKey = "DETECTION_" + std::to_string(i + 1);
                std::string featureValue = findings[i].snippet;
                
                // 첫 번째 스니펫 저장
                if (firstSnippet.empty() && featureValue.length() > 50) {
                    firstSnippet = featureValue.substr(0, 200);
                    std::replace(firstSnippet.begin(), firstSnippet.end(), '\n', ' ');
                    std::replace(firstSnippet.begin(), firstSnippet.end(), '\r', ' ');
                }
                
                // 변수명 추출 (예: "Malicious pattern detected: CreateObject [Variable: xxx]")
                size_t varPos = featureValue.find("[Variable: ");
                if (varPos != std::string::npos) {
                    size_t endPos = featureValue.find("]", varPos);
                    if (endPos != std::string::npos) {
                        std::string varName = featureValue.substr(varPos + 11, endPos - varPos - 11);
                        variableNames.insert(varName);
                    }
                }
                
                // 패턴 추출
                if (reason == "malicious_pattern_detected" || reason == "malicious_pattern_blocked") {
                    size_t colonPos = featureValue.find(": ");
                    if (colonPos != std::string::npos) {
                        size_t bracketPos = featureValue.find(" [", colonPos);
                        if (bracketPos != std::string::npos) {
                            std::string pattern = featureValue.substr(colonPos + 2, bracketPos - colonPos - 2);
                            detectedPatterns.insert(pattern);
                        }
                    }
                }
                
                totalLength += featureValue.length();
                det.addFeature(featureKey, JsValue(featureValue.length() > 500 ? featureValue.substr(0, 500) + "..." : featureValue));
            }
            
            // 요약 정보 추가
            det.addFeature(HookTypeToString(HookType::DETECTION_COUNT), JsValue(static_cast<double>(findings.size())));
            
            // 🎯 상세한 Summary 생성
            std::ostringstream detailedSummary;
            detailedSummary << "Detected " << findings.size() << " instance(s) of " << reason;
            
            // 추가 컨텍스트
            if (!variableNames.empty()) {
                detailedSummary << " in " << variableNames.size() << " variable(s)";
                if (variableNames.size() <= 3) {
                    detailedSummary << " [Variables: ";
                    int count = 0;
                    for (const auto& varName : variableNames) {
                        if (count > 0) detailedSummary << ", ";
                        detailedSummary << varName;
                        count++;
                    }
                    detailedSummary << "]";
                }
            }
            
            // 탐지된 패턴 나열
            if (!detectedPatterns.empty()) {
                detailedSummary << " [Patterns: ";
                int count = 0;
                for (const auto& pattern : detectedPatterns) {
                    if (count > 0) detailedSummary << ", ";
                    detailedSummary << pattern;
                    if (++count >= 5) break;
                }
                if (detectedPatterns.size() > 5) {
                    detailedSummary << ", +" << (detectedPatterns.size() - 5) << " more";
                }
                detailedSummary << "]";
            }
            
            // 코드 스니펫 추가
            if (!firstSnippet.empty()) {
                detailedSummary << ". Example: \"" << firstSnippet;
                if (firstSnippet.length() >= 200) detailedSummary << "...";
                detailedSummary << "\"";
            }
            
            // Severity 정보
            if (det.severity >= 9) {
                detailedSummary << ". CRITICAL - Immediate action required (Severity: " << det.severity << "/10)";
            } else if (det.severity >= 7) {
                detailedSummary << ". HIGH - Review recommended (Severity: " << det.severity << "/10)";
            } else if (det.severity >= 5) {
                detailedSummary << ". MEDIUM - Potential concern (Severity: " << det.severity << "/10)";
            }
            
            det.addFeature(HookTypeToString(HookType::SUMMARY), JsValue(detailedSummary.str()));
            
            core::Log_Info("%sAdding static finding detection: severity %d", logMsg.c_str(), det.severity);
            response.addDetection(det);
        }
    }
    
    if (!categorized.criticalEvents.empty()) {
        htmljs_scanner::Detection criticalDetection;
        criticalDetection.analysisCode = "DA";
        
        // 간접 호출이 있는지 확인
        bool hasIndirectCalls = std::any_of(categorized.criticalEvents.begin(), categorized.criticalEvents.end(),
            [](const HookEvent& e) {
                if (e.name.find("window[\"") != std::string::npos) {
                    auto it = e.metadata.find("access_pattern");
                    if (it != e.metadata.end()) {
                        std::string pattern = JsValueToString(it->second);
                        // 따옴표 제거하여 비교
                        if (pattern.find("indirect_property_access") != std::string::npos) {
                            return true;
                        }
                    }
                }
                return false;
            });
        
        if (hasIndirectCalls) {
            criticalDetection.name = "JSScanner.INDIRECT_PROPERTY_ACCESS";
        } else {
            criticalDetection.name = "JSScanner." + HookTypeToString(categorized.criticalEvents.front().type);
        }
        
        // 🔥 FIX: 이벤트들의 실제 severity 중 최대값을 사용
        int criticalSeverity = 0;
        for (const auto& event : categorized.criticalEvents) {
            criticalSeverity = std::max(criticalSeverity, event.severity);
        }
        
        // 간접 호출 전용 처리
        std::vector<std::string> indirectAccessList;
        
        // 이벤트별로 Feature 추가
        std::map<std::string, int> typeCount;
        for (const auto& event : categorized.criticalEvents) {
            // 간접 호출 처리
            if (event.name.find("window[\"") != std::string::npos) {
                auto it = event.metadata.find("access_pattern");
                if (it != event.metadata.end()) {
                    std::string pattern = convertJsValueToString(it->second);
                    // 따옴표 제거하여 비교
                    if (pattern.find("indirect_property_access") != std::string::npos) {
                        auto propIt = event.metadata.find("property");
                        if (propIt != event.metadata.end()) {
                            std::string propName = convertJsValueToString(propIt->second);
                            // 따옴표 제거
                            propName.erase(std::remove(propName.begin(), propName.end(), '"'), propName.end());
                            indirectAccessList.push_back("window['" + propName + "']");
                        }
                        continue;
                    }
                }
            }
            
            std::string hookType = HookTypeToString(event.type);
            typeCount[hookType]++;
            std::string featureKey = hookType + "_" + std::to_string(typeCount[hookType]);
            
            if (event.type == HookType::FETCH_REQUEST && !event.metadata.empty()) {
                criticalDetection.addFeature(featureKey, JsValue(event.metadata));
            } else if (event.type == HookType::DATA_EXFILTRATION) {
                // 🔥 NEW: DATA_EXFILTRATION은 key 값 포함
                std::string desc = event.name;
                auto keyIt = event.metadata.find("key");
                if (keyIt != event.metadata.end()) {
                    std::string keyValue = convertJsValueToString(keyIt->second);
                    keyValue.erase(std::remove(keyValue.begin(), keyValue.end(), '"'), keyValue.end());
                    desc += "(key: '" + keyValue + "')";
                }
                desc += " (severity: " + std::to_string(event.severity) + ")";
                criticalDetection.addFeature(featureKey, JsValue(desc));
            } else {
                std::string desc = event.name + " (severity: " + std::to_string(event.severity) + ")";
                criticalDetection.addFeature(featureKey, JsValue(desc));
            }
        }
        
        // FETCH_REQUEST 요약 추가 - SummaryGenerator 사용
        int fetchCount = typeCount["FETCH_REQUEST"];
        if (fetchCount > 0) {
            std::string fetchSummary = summaryGenerator_->generateFetchRequestSummary(categorized.criticalEvents);
            criticalDetection.addFeature(HookTypeToString(HookType::FETCH_REQUEST_SUMMARY), JsValue(fetchSummary));
        }
        
        // 🔥 NEW: DATA_EXFILTRATION 요약 추가
        int dataExfilCount = typeCount["DATA_EXFILTRATION"];
        if (dataExfilCount > 0) {
            criticalDetection.addFeature(HookTypeToString(HookType::DETECTION_COUNT), JsValue(std::to_string(dataExfilCount)));
            
            // SUMMARY 생성 (key 값 포함)
            std::vector<std::string> examplesList;
            for (const auto& event : categorized.criticalEvents) {
                if (event.type == HookType::DATA_EXFILTRATION && examplesList.size() < 3) {
                    std::string example = event.name;
                    
                    // metadata에서 key 추출
                    auto keyIt = event.metadata.find("key");
                    if (keyIt != event.metadata.end()) {
                        std::string keyValue = convertJsValueToString(keyIt->second);
                        // 따옴표 제거
                        keyValue.erase(std::remove(keyValue.begin(), keyValue.end(), '"'), keyValue.end());
                        example += "(key: '" + keyValue + "')";
                    }
                    
                    example += " (severity: " + std::to_string(event.severity) + ")";
                    examplesList.push_back(example);
                }
            }
            
            std::string summary = "Detected " + std::to_string(dataExfilCount) + 
                                 " instance(s) of data_exfiltration";
            if (!examplesList.empty()) {
                summary += ". Examples: " + examplesList[0];
                for (size_t i = 1; i < examplesList.size(); ++i) {
                    summary += ", " + examplesList[i];
                }
            }
            criticalDetection.addFeature(HookTypeToString(HookType::SUMMARY), JsValue(summary));
        }
        
        // 간접 호출 요약 추가
        if (!indirectAccessList.empty()) {
            criticalDetection.addFeature(HookTypeToString(HookType::INDIRECT_ACCESS_COUNT), 
                JsValue(static_cast<double>(indirectAccessList.size())));
            
            std::string indirectSummary = "Detected " + std::to_string(indirectAccessList.size()) + 
                                         " indirect property access(es): " + 
                                         std::accumulate(indirectAccessList.begin(), indirectAccessList.end(), std::string(),
                                             [](const std::string& a, const std::string& b) {
                                                 return a.empty() ? b : a + ", " + b;
                                             });
            criticalDetection.addFeature(HookTypeToString(HookType::INDIRECT_ACCESS_SUMMARY), JsValue(indirectSummary));
            
            for (size_t i = 0; i < indirectAccessList.size(); ++i) {
                criticalDetection.addFeature(HookTypeToString(HookType::INDIRECT_ACCESS_PREFIX) + std::to_string(i + 1), 
                    JsValue(indirectAccessList[i]));
            }
            criticalSeverity = 10; // 간접 호출은 최고 위험도
        }
        
        // Severity 설정
        criticalDetection.severity = criticalSeverity;
        
        // 🔥 FIX: Severity가 0이면 추가하지 않음 (노이즈 제거)
        if (criticalSeverity > 0) {
            core::Log_Info("%sAdding critical events detection with severity %d", logMsg.c_str(), criticalSeverity);
            response.addDetection(criticalDetection);
        } else {
            core::Log_Info("%sSkipping critical events detection with severity 0 (low risk)", logMsg.c_str());
        }
    }

    core::Log_Warn("%s=== addDynamicAnalysisResults COMPLETED, Total detections now: %zu ===", logMsg.c_str(), response.getDetections().size());
}

void ResponseGenerator::addRouteHints(AnalysisResponse& response, const std::vector<htmljs_scanner::Detection>& staticFindings) {
    bool hasHtmlContent = std::any_of(staticFindings.begin(), staticFindings.end(),
        [](const htmljs_scanner::Detection& f) { return f.reason.find("script") != std::string::npos || f.reason.find("html") != std::string::npos; });
        
    if (hasHtmlContent) {
        RouteHint hint("JSScanner", "HTML script tag detected");
        hint.addTrigger("script-tag-detected");
        hint.addTrigger("dynamic-html-generation");
        response.addRouteHint(hint);
    }
        
    bool hasUrls = std::any_of(staticFindings.begin(), staticFindings.end(),
        [](const htmljs_scanner::Detection& f) { return f.reason.find("url") != std::string::npos; });
        
    if (hasUrls) {
        RouteHint hint("NetworkAnalyzer", "External URL communication detected");
        hint.addTrigger("external-url-detected");
        hint.addTrigger("network-communication");
        response.addRouteHint(hint);
    }
        
    bool hasEval = std::any_of(staticFindings.begin(), staticFindings.end(),
        [](const htmljs_scanner::Detection& f) { return f.reason.find("eval") != std::string::npos; });
        
    if (hasEval) {
        RouteHint hint("CodeInjectionAnalyzer", "Dynamic code execution detected");
        hint.addTrigger("eval-function-detected");
        hint.addTrigger("code-injection-risk");
        response.addRouteHint(hint);
    }
}

std::string ResponseGenerator::generateAnalysisResponse(const std::string& taskId, const std::vector<htmljs_scanner::Detection>& staticFindings,
    std::vector<std::string>& extractedUrls, long long executionTimeMs, JSAnalyzerContext* a_ctx) {
    AnalysisResponse response = generateAnalysisResponseObject(taskId, staticFindings, extractedUrls, executionTimeMs, a_ctx);
    try {
        return response.toJson().dump(4); // Pretty print with 4 spaces
    }
    catch (const std::exception& e) {
        return createFallbackErrorResponse(taskId, e.what());
    }
}

AnalysisResponse ResponseGenerator::generateAnalysisResponseObject(const std::string& taskId, const std::vector<htmljs_scanner::Detection>& staticFindings,
    std::vector<std::string>& extractedUrls, long long executionTimeMs, JSAnalyzerContext* a_ctx) {
    return buildAnalysisResponse(taskId, staticFindings, extractedUrls, executionTimeMs, a_ctx);
}

// ============================================================================
// Taint Pattern Grouping Implementation
// ============================================================================

std::vector<ResponseGenerator::TaintGroup> ResponseGenerator::groupTaintedValues(const std::vector<TaintedValue*>& taintedValues) const {
    std::vector<TaintGroup> groups;
    
    // 1. String.fromCharCode로 만들어진 연속 문자들 그룹화
    std::vector<int> currentGroup;
    std::string accumulatedString;
    
    for (size_t i = 0; i < taintedValues.size(); ++i) {
        auto* taint = taintedValues[i];
        std::string func = taint->getSourceFunction();
        std::string value = JsValueToString(taint->getValue());
        
        if (func == "String.fromCharCode" && value.length() == 1) {
            currentGroup.push_back(i);
            accumulatedString += value;
        } else {
            // 이전 그룹 완성
            if (currentGroup.size() >= 2) {
                TaintGroup group;
                group.type = "String Construction";
                group.description = "Characters combined using String.fromCharCode";
                group.taintIndices = currentGroup;
                group.combinedValue = accumulatedString;
                group.maxLevel = 5;
                group.threat = evaluateThreat(accumulatedString);
                
                for (int idx : currentGroup) {
                    group.maxLevel = std::max(group.maxLevel, static_cast<int>(taintedValues[idx]->getTaintLevel()));
                }
                
                groups.push_back(group);
                core::Log_Info("%s Grouped String: \"%s\" (%zu chars) - Threat: %s", 
                              logMsg.c_str(), accumulatedString.c_str(), currentGroup.size(), group.threat.c_str());
            }
            currentGroup.clear();
            accumulatedString.clear();
        }
    }
    
    // 마지막 그룹 처리
    if (currentGroup.size() >= 2) {
        TaintGroup group;
        group.type = "String Construction";
        group.description = "Characters combined using String.fromCharCode";
        group.taintIndices = currentGroup;
        group.combinedValue = accumulatedString;
        group.maxLevel = 5;
        group.threat = evaluateThreat(accumulatedString);
        
        for (int idx : currentGroup) {
            group.maxLevel = std::max<int>(group.maxLevel, taintedValues[idx]->getTaintLevel());
        }
        
        groups.push_back(group);
    }
    
    // 2. atob 디코딩 결과 그룹화
    for (size_t i = 0; i < taintedValues.size(); ++i) {
        auto* taint = taintedValues[i];
        if (taint->getSourceFunction() == "atob") {
            TaintGroup group;
            group.type = "Base64 Decoding";
            group.description = "Decoded data from Base64";
            group.taintIndices.push_back(i);
            group.combinedValue = JsValueToString(taint->getValue());
            group.maxLevel = taint->getTaintLevel();
            group.threat = evaluateThreat(group.combinedValue);
            
            groups.push_back(group);
            core::Log_Info("%s  Decoded: \"%s\" - Threat: %s", logMsg.c_str(), group.combinedValue.c_str(), group.threat.c_str());
        }
    }
    
    return groups;
}

std::string ResponseGenerator::evaluateThreat(const std::string& value) const {
    std::string lowerValue = value;
    std::transform(lowerValue.begin(), lowerValue.end(), lowerValue.begin(), ::tolower);
    
    // 위협 유형 판별
    if (lowerValue.find("http://") != std::string::npos || lowerValue.find("https://") != std::string::npos) {
        // 악성 도메인 체크
        if (lowerValue.find("evil") != std::string::npos || lowerValue.find("malware") != std::string::npos) {
            return "CRITICAL: Malicious URL";
        }
        return "HIGH: External URL";
    }
    
    if (lowerValue.find("eval") != std::string::npos) {
        return "CRITICAL: Dynamic Code Execution (eval)";
    }
    
    if (lowerValue.find("document.write") != std::string::npos || 
        lowerValue.find("innerhtml") != std::string::npos) {
        return "HIGH: DOM Manipulation (XSS Risk)";
    }
    
    if (lowerValue.find("activexobject") != std::string::npos) {
        return "CRITICAL: ActiveX Exploitation";
    }
    
    if (lowerValue.find("wscript") != std::string::npos || lowerValue.find("shell") != std::string::npos) {
        return "CRITICAL: System Command Execution";
    }
    
    if (lowerValue.find("atob") != std::string::npos || lowerValue.find("fromcharcode") != std::string::npos) {
        return "MEDIUM: Obfuscation Function";
    }
    
    if (lowerValue.find("<script") != std::string::npos || lowerValue.find("<iframe") != std::string::npos) {
        return "HIGH: HTML Injection";
    }
    
    return "MEDIUM: Suspicious Pattern";
}

void ResponseGenerator::addTaintGroupsToDetection(htmljs_scanner::Detection& detection, const std::vector<TaintGroup>& groups, int& maxSeverity) {
    if (groups.empty()) return;
    
    // 그룹별로 요약 정보 추가
    int groupNum = 0;
    for (const auto& group : groups) {
        groupNum++;
        std::string featureKey = "TAINT_PATTERN_" + std::to_string(groupNum);
        
        std::stringstream ss;
        ss << "[" << group.type << "] ";
        ss << group.combinedValue;
        ss << " (from " << group.taintIndices.size() << " taints, ";
        ss << "level: " << group.maxLevel << ", ";
        ss << "threat: " << group.threat << ")";
        
        detection.addFeature(featureKey, JsValue(ss.str()));
        maxSeverity = std::max<int>(maxSeverity, group.maxLevel);
        
    }
    
    // 전체 요약
    detection.addFeature(HookTypeToString(HookType::TAINT_PATTERNS_SUMMARY), 
                        JsValue("Found " + std::to_string(groups.size()) + " meaningful attack patterns"));
}

// ============================================================================
// Crypto Operation Grouping Implementation
// ============================================================================

std::vector<ResponseGenerator::CryptoGroup> ResponseGenerator::groupConsecutiveCryptoOperations(const std::vector<HookEvent>& allEvents) const {
    std::vector<CryptoGroup> groups;
    
    core::Log_Debug("%sStarting crypto operation grouping from %zu events", logMsg.c_str(), allEvents.size());
    
    // 🔥 전략 변경: eval 호출을 기준으로 역추적하여 그룹 생성
    // 각 eval 호출 전에 나온 crypto 작업들을 하나의 그룹으로
    
    std::vector<size_t> evalIndices;
    for (size_t i = 0; i < allEvents.size(); ++i) {
        if (allEvents[i].type == HookType::FUNCTION_CALL && allEvents[i].name == "eval") {
            evalIndices.push_back(i);
        }
    }
    
    core::Log_Debug("%sFound %zu eval calls", logMsg.c_str(), evalIndices.size());
    
    size_t currentCryptoStart = 0;
    
    for (size_t evalIdx : evalIndices) {
        CryptoGroup group;
        group.hasEval = true;
        group.events.push_back(allEvents[evalIdx]); // eval 자체 추가
        group.endTime = allEvents[evalIdx].timestamp;
        
        core::Log_Debug("%s  Processing eval at index %zu", logMsg.c_str(), evalIdx);
        
        // eval 이전의 crypto 작업들을 역순으로 수집
        std::vector<HookEvent> cryptoBeforeEval;
        int nonCryptoCount = 0;
        
        for (int i = static_cast<int>(evalIdx) - 1; i >= static_cast<int>(currentCryptoStart); --i) {
            // 🔥 최대 제한까지만 수집
            if (cryptoBeforeEval.size() >= AnalysisConstants::MAX_CRYPTO_CHAIN_SIZE) {
                core::Log_Info("%s    Reached max crypto operations limit (%zu), stopping collection",
                              logMsg.c_str(), static_cast<size_t>(AnalysisConstants::MAX_CRYPTO_CHAIN_SIZE));
                break;
            }

            const auto& event = allEvents[i];

            // CRYPTO_OPERATION이거나 난독화 관련 FUNCTION_CALL인 경우
            bool isCryptoRelated = (event.type == HookType::CRYPTO_OPERATION) ||
                                   (event.type == HookType::FUNCTION_CALL &&
                                    AnalysisConstants::OBFUSCATION_FUNCTIONS.count(event.name) > 0);

            if (isCryptoRelated) {
                cryptoBeforeEval.push_back(event);
                core::Log_Debug("%s    Found crypto: %s at index %d", logMsg.c_str(), event.name.c_str(), i);
                nonCryptoCount = 0; // 리셋
            } else {
                nonCryptoCount++;
                core::Log_Debug("%s    Skipping non-crypto: %s - %s", 
                               logMsg.c_str(), HookTypeToString(event.type).c_str(), event.name.c_str());

                // 연속된 non-crypto 이벤트가 10개 이상이면 중단 (여유 증가)
                if (nonCryptoCount >= 10) {
                    core::Log_Debug("%s    Breaking: too many non-crypto events", logMsg.c_str());
                    break;
                }
            }
        }
        
        // 역순으로 모았으므로 뒤집기
        std::reverse(cryptoBeforeEval.begin(), cryptoBeforeEval.end());
        
        if (!cryptoBeforeEval.empty()) {
            group.events.insert(group.events.begin(), cryptoBeforeEval.begin(), cryptoBeforeEval.end());
            group.startTime = cryptoBeforeEval.front().timestamp;
            group.description = "Obfuscation + eval: " + std::to_string(cryptoBeforeEval.size()) + " operations";
            
            groups.push_back(group);
            core::Log_Debug("%s  Group %zu: %zu crypto ops -> eval", 
                          logMsg.c_str(), groups.size(), cryptoBeforeEval.size());
            
            // 다음 그룹은 이 eval 이후부터 시작
            currentCryptoStart = evalIdx + 1;
        }
    }
    
    // 🔥 난독화 함수 목록 (재사용)
    std::set<std::string> obfuscationFunctions = {
        "atob", "btoa", "escape", "unescape",
        "decodeURI", "decodeURIComponent", "encodeURI", "encodeURIComponent",
        "String.fromCharCode", "parseInt", "Array.join"
    };
    
    // eval 없이 남은 crypto 작업들을 별도 그룹으로
    CryptoGroup remainingGroup;
    for (size_t i = currentCryptoStart; i < allEvents.size(); ++i) {
        // 🔥 최대 1000개까지만 수집
        if (remainingGroup.events.size() >= 1000) {
            core::Log_Info("%sReached max crypto operations limit (1000) for remaining group, stopping collection", logMsg.c_str());
            break;
        }

        const auto& event = allEvents[i];
        bool isCryptoRelated = (event.type == HookType::CRYPTO_OPERATION) ||
                               (event.type == HookType::FUNCTION_CALL &&
                                obfuscationFunctions.count(event.name) > 0);

        if (isCryptoRelated) {
            if (remainingGroup.events.empty()) {
                remainingGroup.startTime = event.timestamp;
            }
            remainingGroup.events.push_back(event);
            remainingGroup.endTime = event.timestamp;
        }
    }
    
    if (!remainingGroup.events.empty()) {
        remainingGroup.hasEval = false;
        remainingGroup.description = "Obfuscation chain: " + std::to_string(remainingGroup.events.size()) + " operations (no eval)";
        groups.push_back(remainingGroup);
        core::Log_Debug("%s  Group %zu: %zu crypto ops (remaining, no eval)", 
                      logMsg.c_str(), groups.size(), remainingGroup.events.size());
    }
    
    // eval 이전에 아무 crypto도 없었던 경우를 위한 처리
    // 첫 eval 이전의 모든 crypto를 하나의 그룹으로
    if (groups.empty() && !evalIndices.empty()) {
        CryptoGroup firstGroup;
        for (size_t i = 0; i < evalIndices[0]; ++i) {
            // 🔥 최대 1000개까지만 수집
            if (firstGroup.events.size() >= 1000) {
                core::Log_Info("%sReached max crypto operations limit (1000) for first group, stopping collection", logMsg.c_str());
                break;
            }

            if (allEvents[i].type == HookType::CRYPTO_OPERATION) {
                if (firstGroup.events.empty()) {
                    firstGroup.startTime = allEvents[i].timestamp;
                }
                firstGroup.events.push_back(allEvents[i]);
                firstGroup.endTime = allEvents[i].timestamp;
            }
        }
        
        if (!firstGroup.events.empty()) {
            firstGroup.hasEval = false;
            firstGroup.description = "Obfuscation chain: " + std::to_string(firstGroup.events.size()) + " operations";
            groups.push_back(firstGroup);
            core::Log_Debug("%s  Group %zu: %zu crypto ops (before first eval)", 
                          logMsg.c_str(), groups.size(), firstGroup.events.size());
        }
    }
    
    // 🔥 Array.join만 있고 10개 미만인 그룹 필터링
    std::vector<CryptoGroup> filteredGroups;
    for (const auto& group : groups) {
        int arrayJoinCount = 0;
        int totalObfuscationCount = 0;

        for (const auto& event : group.events) {
            if (event.type == HookType::CRYPTO_OPERATION ||
                (event.type == HookType::FUNCTION_CALL && event.name != "eval")) {
                totalObfuscationCount++;
                if (event.name == "Array.join") {
                    arrayJoinCount++;
                }
            }
        }

        // Array.join만 있고 10개 미만이면 그룹 제외
        int nonArrayJoinCount = totalObfuscationCount - arrayJoinCount;
        if (arrayJoinCount > 0 && arrayJoinCount < 10 && nonArrayJoinCount == 0) {
            core::Log_Info("%sFiltering out crypto group: Array.join count (%d) below threshold (10) with no other obfuscation functions", 
                          logMsg.c_str(), arrayJoinCount);
            continue;
        }

        filteredGroups.push_back(group);
    }

    core::Log_Info("%sCrypto grouping result: %zu independent groups (filtered from %zu)", 
                  logMsg.c_str(), filteredGroups.size(), groups.size());
    return filteredGroups;
}

void ResponseGenerator::addCryptoGroupDetection(AnalysisResponse& response, const CryptoGroup& group, int groupIndex, TaintTracker* taintTracker, int& orderCounter) {
    htmljs_scanner::Detection detection;
    detection.analysisCode = "DA";
    detection.name = "JSScanner.OBFUSCATION_CHAIN_" + std::to_string(groupIndex);
    
    // 🔥 난독화 함수 목록
    std::set<std::string> obfuscationFunctions = {
        "atob", "btoa", "escape", "unescape",
        "decodeURI", "decodeURIComponent", "encodeURI", "encodeURIComponent",
        "String.fromCharCode", "parseInt", "Array.join"
    };

    // Crypto 체인 문자열 생성 - CRYPTO_OPERATION과 난독화 FUNCTION_CALL 모두 포함
    std::vector<std::string> cryptoChain;
    int arrayJoinCount = 0;
    for (const auto& event : group.events) {
        if (event.type == HookType::CRYPTO_OPERATION) {
            cryptoChain.push_back(event.name);
        } else if (event.type == HookType::FUNCTION_CALL &&
                   obfuscationFunctions.count(event.name) > 0 &&
                   event.name != "eval") {  // eval은 제외
            cryptoChain.push_back(event.name);
            if (event.name == "Array.join") {
                arrayJoinCount++;
            }
        }
    }

    // 🔥 Array.join이 10개 미만이고 다른 난독화 함수가 없으면 그룹 무효화
    int nonArrayJoinCount = static_cast<int>(cryptoChain.size()) - arrayJoinCount;
    if (arrayJoinCount > 0 && arrayJoinCount < 10 && nonArrayJoinCount == 0) {
        core::Log_Info("%sSkipping crypto group: Array.join count (%d) below threshold (10) with no other obfuscation functions", 
                      logMsg.c_str(), arrayJoinCount);
        return;  // 그룹을 추가하지 않음
    }
    
    int maxSeverity = 5;
    
    // Feature 추가
    if (!cryptoChain.empty()) {
        std::string chainStr = buildCryptoChainString(cryptoChain);
        detection.addFeature(HookTypeToString(HookType::CRYPTO_OPERATION_PREFIX) + "1", JsValue(chainStr));
        maxSeverity = std::max(maxSeverity, 7);
    }
    
    if (group.hasEval) {
        detection.addFeature(HookTypeToString(HookType::FUNCTION_CALL_PREFIX) + "1", JsValue("eval(deobfuscated_code)"));
        maxSeverity = std::max(maxSeverity, 10);
    }
    
    // Duration 추가
    long long duration = group.endTime - group.startTime;
    detection.addFeature(HookTypeToString(HookType::DURATION_MS), JsValue(static_cast<double>(duration)));
    detection.addFeature(HookTypeToString(HookType::TIME_RANGE), JsValue("From " + std::to_string(group.startTime) + " to " + std::to_string(group.endTime)));
    
    // 🔥 Taint는 각 그룹에서 처리하지 않고, 전체 요약만 제공
    // 이유: 함수 이름으로 필터링하면 중복이 발생하고, timestamp가 없어서 정확한 필터링 불가능
    
    detection.severity = maxSeverity;
    
    core::Log_Info("%sAdding crypto group detection: %s with severity %d", 
                  logMsg.c_str(), detection.name.c_str(), maxSeverity);
    addDetectionWithOrder(response, detection, orderCounter);
}

// ⚠️ REMOVED: generateFetchRequestSummary() - now using SummaryGenerator::generateFetchRequestSummary()

// 🆕 DOM 조작에서 발견된 URL 수집
void ResponseGenerator::collectDomUrls(const std::vector<HookEvent>& domEvents) {
    for (const auto& event : domEvents) {
        // external_url 추출
        auto it = event.metadata.find("external_url");
        if (it != event.metadata.end()) {
            std::string url = convertJsValueToString(it->second);
            
            // 따옴표 제거
            url.erase(std::remove(url.begin(), url.end(), '"'), url.end());
            url.erase(std::remove(url.begin(), url.end(), '\\'), url.end());
            
            if (!url.empty() && url != "null" && url != "undefined") {
                domExtractedUrls_.push_back(url);
                core::Log_Info("%sCollected URL from DOM manipulation: %s", logMsg.c_str(), url.c_str());
            }
        }
    }
}

// 🔥 NEW: 외부 통신 분석
nlohmann::json ResponseGenerator::analyzeExternalCommunications(
    const std::vector<UrlMetadata>& urlMetadataList) {
    
    nlohmann::json result = nlohmann::json::array();
    
    if (scanTargetUrl_.empty()) {
        return result;  // 검사 URL이 없으면 비교 불가
    }
    
    for (const auto& urlMeta : urlMetadataList) {
        // 외부 URL인지 확인
        bool isExternal = UrlComparator::isExternalUrl(scanTargetUrl_, urlMeta.url);
        
        if (isExternal) {
            nlohmann::json comm;
            comm["url"] = urlMeta.url;
            comm["source"] = urlMeta.source;
            comm["extension"] = urlMeta.extension;
            comm["has_extension"] = urlMeta.hasExtension;
            comm["is_suspicious"] = urlMeta.isSuspicious;
            comm["scan_target"] = scanTargetUrl_;
            
            // 위험도 계산
            int risk = 5;  // 기본: 외부 통신
            std::string riskReason = "External domain communication";
            
            if (urlMeta.isSuspicious) {
                risk = 10;
                riskReason = "Suspicious file from external domain: " + urlMeta.extension;
            }
            
            comm["risk_level"] = risk;
            comm["risk_reason"] = riskReason;
            
            result.push_back(comm);
        }
    }
    
    return result;
}


// 🔥 NEW: 외부 통신 Detection 추가 (기존 포맷에 맞춤)
void ResponseGenerator::addExternalCommunicationDetection(
    AnalysisResponse& response,
    const std::vector<UrlMetadata>& urlMetadataList,
    int& orderCounter) {
    
    int totalCount = 0;
    int criticalCount = 0;
    std::vector<std::string> externalUrls;
    std::vector<std::string> threatTypes;
    
    // URL 분석
    for (const auto& urlMeta : urlMetadataList) {
        bool isExternal = UrlComparator::isExternalUrl(scanTargetUrl_, urlMeta.url);
        
        if (isExternal) {
            totalCount++;
            
            // 도메인 추출 (프로토콜 제거)
            std::string shortUrl = urlMeta.url;
            size_t pos = shortUrl.find("://");
            if (pos != std::string::npos) {
                shortUrl = shortUrl.substr(pos + 3);
            }
            
            // 포맷: "source → domain/path (ext)"
            std::string entry = urlMeta.source + " → " + shortUrl;
            if (urlMeta.hasExtension) {
                entry += " (" + urlMeta.extension + ")";
            }
            
            if (urlMeta.isSuspicious) {
                criticalCount++;
                externalUrls.push_back(entry);
                
                // 위협 타입 분류
                std::string ext = urlMeta.extension;
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                
                if (ext == ".exe" || ext == ".dll" || ext == ".bat" || 
                    ext == ".cmd" || ext == ".ps1" || ext == ".msi" || ext == ".jar") {
                    if (std::find(threatTypes.begin(), threatTypes.end(), "executable") 
                        == threatTypes.end()) {
                        threatTypes.push_back("executable");
                    }
                } else if (ext == ".php" || ext == ".asp" || ext == ".aspx" || 
                           ext == ".jsp" || ext == ".cgi" || ext == ".py") {
                    if (std::find(threatTypes.begin(), threatTypes.end(), "script") 
                        == threatTypes.end()) {
                        threatTypes.push_back("script");
                    }
                }
            }
        }
    }
    
    // Detection 생성 (critical만 보고)
    if (criticalCount > 0) {
        htmljs_scanner::Detection detection;
        detection.name = "JSScanner.EXTERNAL_COMMUNICATION";
        detection.severity = 10;
        detection.detectionOrder = orderCounter++;
        
        // Features 구성
        detection.features[HookTypeToString(HookType::EXTERNAL_COUNT)] = JsValue(std::to_string(totalCount));
        detection.features[HookTypeToString(HookType::CRITICAL_COUNT)] = JsValue(std::to_string(criticalCount));
        
        // 위협 요약
        std::string threats;
        if (!threatTypes.empty()) {
            threats = std::to_string(criticalCount) + " ";
            for (size_t i = 0; i < threatTypes.size(); ++i) {
                threats += threatTypes[i];
                if (i < threatTypes.size() - 1) {
                    threats += "/";
                }
            }
            threats += " download";
            if (criticalCount > 1) {
                threats += "s";
            }
            threats += " detected";
        } else {
            threats = std::to_string(criticalCount) + " suspicious download";
            if (criticalCount > 1) {
                threats += "s";
            }
            threats += " detected";
        }
        detection.features[HookTypeToString(HookType::THREATS)] = JsValue(threats);
        
        // 외부 URL 목록 (최대 10개)
        int displayCount = std::min(10, static_cast<int>(externalUrls.size()));
        for (int i = 0; i < displayCount; ++i) {
            std::string key = HookTypeToString(HookType::EXTERNAL_PREFIX) + std::to_string(i + 1);
            detection.features[key] = JsValue(externalUrls[i]);
        }
        
        // 검사 대상 URL
        detection.features[HookTypeToString(HookType::SCAN_TARGET)] = JsValue(scanTargetUrl_);
        
        // SUMMARY 생성
        std::string summary = "Detected " + std::to_string(totalCount) + 
                            " external connection(s) including " + 
                            std::to_string(criticalCount) + " high-risk download(s). ";
        
        if (criticalCount >= 3) {
            summary += "CRITICAL - Immediate action required (Severity: 10/10)";
        } else if (criticalCount >= 1) {
            summary += "CRITICAL - High-risk external downloads detected (Severity: 10/10)";
        }
        
        detection.features[HookTypeToString(HookType::SUMMARY)] = JsValue(summary);
        response.addDetection(detection);
    }
}
