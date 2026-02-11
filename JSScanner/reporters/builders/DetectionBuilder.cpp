#include "pch.h"
#include "DetectionBuilder.h"
#include "../../hooks/HookType.h"
#include "../../model/JsValueVariant.h"
#include <sstream>
#include <algorithm>

DetectionBuilder::DetectionBuilder() {
}

std::string DetectionBuilder::convertJsValueToString(const JsValue& val) const {
    return JsValueToString(val);
}

int DetectionBuilder::calculateSeverity(const std::string& reason) const {
    if (reason.find("eval") != std::string::npos) return 6;
    if (reason.find("activex") != std::string::npos) return 6;
    if (reason.find("wscript") != std::string::npos) return 6;
    if (reason.find("document_write") != std::string::npos) return 4;
    if (reason.find("window_location_redirect") != std::string::npos) return 5;
    if (reason.find("url") != std::string::npos) return 5;
    return 3; // Default
}

std::string DetectionBuilder::truncateString(const std::string& str, size_t maxLen) const {
    if (str.length() <= maxLen) return str;
    return str.substr(0, maxLen) + "...";
}

htmljs_scanner::Detection DetectionBuilder::buildDomManipulationDetection(
    const std::vector<HookEvent>& domEvents,
    const std::string& summary) {
    
    htmljs_scanner::Detection detection;
    detection.analysisCode = "DA";
    detection.name = "JSScanner.DOM_MANIPULATION";
    
    // document.write와 기타 DOM 이벤트 분리
    std::vector<HookEvent> documentWriteEvents;
    std::vector<HookEvent> otherDomEvents;
    
    for (const auto& event : domEvents) {
        if (event.name == "document.write") {
            documentWriteEvents.push_back(event);
        } else {
            otherDomEvents.push_back(event);
        }
    }
    
    int maxSeverity = 8;
    
    // document.write 처리
    for (size_t i = 0; i < documentWriteEvents.size(); ++i) {
        const auto& event = documentWriteEvents[i];
        std::string featureKey = "document_write_" + std::to_string(i + 1);
        
        std::stringstream ss;
        ss << "document.write(";
        
        if (!event.args.empty()) {
            std::string content = convertJsValueToString(event.args[0]);
            ss << truncateString(content, 150);
        }
        ss << ")";
        
        // metadata 플래그 추가
        std::vector<std::string> flags;
        
        if (event.metadata.find("contains_script") != event.metadata.end()) {
            flags.push_back("Contains <script>");
            maxSeverity = std::max(maxSeverity, 9);
        }
        if (event.metadata.find("contains_iframe") != event.metadata.end()) {
            flags.push_back("Contains <iframe>");
            maxSeverity = std::max(maxSeverity, 9);
        }
        if (event.metadata.find("contains_html") != event.metadata.end()) {
            flags.push_back("Full HTML injection");
            maxSeverity = std::max(maxSeverity, 8);
        }
        if (event.metadata.find("external_url") != event.metadata.end()) {
            std::string url = convertJsValueToString(event.metadata.at("external_url"));
            flags.push_back("External URL: " + url);
        }
        if (event.metadata.find("obfuscation_detected") != event.metadata.end()) {
            flags.push_back("Obfuscation detected");
            maxSeverity = std::max(maxSeverity, 9);
        }
        
        if (!flags.empty()) {
            ss << " [";
            for (size_t j = 0; j < flags.size(); ++j) {
                if (j > 0) ss << ", ";
                ss << flags[j];
            }
            ss << "]";
        }
        
        detection.addFeature(featureKey, JsValue(ss.str()));
    }
    
    // 기타 DOM 조작 추가
    std::map<std::string, int> funcCount;
    for (const auto& event : otherDomEvents) {
        funcCount[event.name]++;
        std::string featureKey = event.name + "_" + std::to_string(funcCount[event.name]);
        
        std::stringstream ss;
        ss << event.name;
        
        if (!event.args.empty()) {
            ss << "(";
            for (size_t i = 0; i < std::min(event.args.size(), size_t(2)); ++i) {
                if (i > 0) ss << ", ";
                std::string argStr = convertJsValueToString(event.args[i]);
                ss << truncateString(argStr, 50);
            }
            ss << ")";
        }
        
        detection.addFeature(featureKey, JsValue(ss.str()));
    }
    
    detection.severity = maxSeverity;
    detection.addFeature(HookTypeToString(HookType::SUMMARY), JsValue(summary));
    detection.addFeature(HookTypeToString(HookType::EVENT_COUNT), JsValue(static_cast<double>(domEvents.size())));
    
    return detection;
}

htmljs_scanner::Detection DetectionBuilder::buildLocationChangeDetection(
    const std::vector<HookEvent>& locationEvents,
    const std::string& summary) {
    
    htmljs_scanner::Detection detection;
    detection.analysisCode = "DA";
    detection.name = "JSScanner.LOCATION_CHANGE";
    detection.severity = 7;
    
    for (size_t i = 0; i < locationEvents.size(); ++i) {
        const auto& event = locationEvents[i];
        std::string featureKey = HookTypeToString(HookType::REDIRECT_PREFIX) + std::to_string(i + 1);
        std::string featureValue = event.name;
        
        if (!event.args.empty()) {
            std::string url = convertJsValueToString(event.args[0]);
            featureValue += " -> " + url;
        }
        
        detection.addFeature(featureKey, JsValue(featureValue));
    }
    
    detection.addFeature(HookTypeToString(HookType::SUMMARY), JsValue(summary));
    detection.addFeature(HookTypeToString(HookType::REDIRECT_COUNT), JsValue(static_cast<double>(locationEvents.size())));
    
    return detection;
}

htmljs_scanner::Detection DetectionBuilder::buildAddrManipulationDetection(
    const std::vector<HookEvent>& addrEvents,
    const std::string& summary) {
    
    htmljs_scanner::Detection detection;
    detection.analysisCode = "DA";
    detection.name = "JSScanner.ADDR_MANIPULATION";
    detection.severity = 8;
    
    for (size_t i = 0; i < addrEvents.size(); ++i) {
        const auto& event = addrEvents[i];
        std::string featureKey = HookTypeToString(HookType::MANIPULATION_PREFIX) + std::to_string(i + 1);
        detection.addFeature(featureKey, JsValue(event.name));
    }
    
    detection.addFeature(HookTypeToString(HookType::SUMMARY), JsValue(summary));
    detection.addFeature(HookTypeToString(HookType::MANIPULATION_COUNT), JsValue(static_cast<double>(addrEvents.size())));
    
    return detection;
}

htmljs_scanner::Detection DetectionBuilder::buildEnvironmentDetection(
    const std::vector<HookEvent>& envEvents,
    const std::string& summary) {
    
    htmljs_scanner::Detection detection;
    detection.analysisCode = "DA";
    detection.name = "JSScanner.ENVIRONMENT_DETECTION";
    detection.severity = 6;
    
    std::set<std::string> detectedProperties;
    for (const auto& event : envEvents) {
        detectedProperties.insert(event.name);
    }
    
    int idx = 1;
    for (const auto& prop : detectedProperties) {
        std::string featureKey = HookTypeToString(HookType::DETECTED_PREFIX) + std::to_string(idx++);
        detection.addFeature(featureKey, JsValue(prop));
    }
    
    detection.addFeature(HookTypeToString(HookType::SUMMARY), JsValue(summary));
    detection.addFeature(HookTypeToString(HookType::PROPERTY_COUNT), JsValue(static_cast<double>(detectedProperties.size())));
    
    return detection;
}

htmljs_scanner::Detection DetectionBuilder::buildCryptoDetection(
    const std::vector<HookEvent>& cryptoEvents,
    bool hasEval,
    const std::string& summary) {
    
    htmljs_scanner::Detection detection;
    detection.analysisCode = "DA";
    detection.name = "JSScanner.OBFUSCATION_CHAINS";
    
    int maxSeverity = hasEval ? 10 : 7;
    
    detection.severity = maxSeverity;
    detection.addFeature(HookTypeToString(HookType::SUMMARY), JsValue(summary));
    detection.addFeature(HookTypeToString(HookType::EVAL_DETECTED), JsValue(hasEval ? "true" : "false"));
    
    return detection;
}

htmljs_scanner::Detection DetectionBuilder::buildAttackChainDetection(
    const std::vector<AttackChain>& chains,
    const std::string& summary) {
    
    htmljs_scanner::Detection detection;
    detection.analysisCode = "DA";
    detection.name = "JSScanner.ATTACK_CHAIN";
    
    int highestSeverity = 0;
    for (const auto& chain : chains) {
        highestSeverity = std::max(highestSeverity, chain.getFinalSeverity());
    }
    
    detection.severity = highestSeverity > 0 ? highestSeverity : 7;
    detection.addFeature(HookTypeToString(HookType::SUMMARY), JsValue(summary));
    detection.addFeature(HookTypeToString(HookType::CHAIN_COUNT), JsValue(static_cast<double>(chains.size())));
    
    return detection;
}

htmljs_scanner::Detection DetectionBuilder::buildStaticFindingDetection(
    const std::string& reason,
    const std::vector<htmljs_scanner::Detection>& findings,
    const std::string& summary) {
    
    htmljs_scanner::Detection detection;
    detection.analysisCode = "DA";
    
    // 🔥 HookType을 사용하여 reason을 Detection 이름과 severity로 변환
    auto [detectionType, severity] = ReasonToDetectionType(reason);
    detection.name = "JSScanner." + HookTypeToString(detectionType);
    detection.severity = severity;
    
    // findings를 Feature로 추가
    for (size_t i = 0; i < findings.size(); ++i) {
        std::string featureKey = "DETECTION_" + std::to_string(i + 1);
        std::string featureValue = findings[i].snippet;
        detection.addFeature(featureKey, JsValue(truncateString(featureValue, 500)));
    }
    
    detection.addFeature(HookTypeToString(HookType::DETECTION_COUNT), JsValue(static_cast<double>(findings.size())));
    detection.addFeature(HookTypeToString(HookType::SUMMARY), JsValue(summary));
    
    return detection;
}

htmljs_scanner::Detection DetectionBuilder::buildCriticalEventsDetection(
    const std::vector<HookEvent>& criticalEvents,
    const std::string& name,
    const std::string& summary) {
    
    htmljs_scanner::Detection detection;
    detection.analysisCode = "DA";
    detection.name = name;
    
    // 🔥 이벤트들 중 최대 severity 사용
    int maxSeverity = 0;
    for (const auto& event : criticalEvents) {
        maxSeverity = std::max(maxSeverity, event.severity);
    }
    detection.severity = maxSeverity > 0 ? maxSeverity : 9;  // 기본값 9
    
    std::map<std::string, int> typeCount;
    for (const auto& event : criticalEvents) {
        std::string hookType = HookTypeToString(event.type);
        typeCount[hookType]++;
        std::string featureKey = hookType + "_" + std::to_string(typeCount[hookType]);
        
        if (event.type == HookType::FETCH_REQUEST && !event.metadata.empty()) {
            detection.addFeature(featureKey, JsValue(event.metadata));
        } else {
            std::string desc = event.name + " (severity: " + std::to_string(event.severity) + ")";
            detection.addFeature(featureKey, JsValue(desc));
        }
    }
    
    detection.addFeature(HookTypeToString(HookType::SUMMARY), JsValue(summary));
    
    return detection;
}
