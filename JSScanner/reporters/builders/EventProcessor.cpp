#include "pch.h"
#include "EventProcessor.h"
#include "../../hooks/HookType.h"
#include "../../model/JsValueVariant.h"

EventProcessor::CategorizedEvents EventProcessor::categorizeEvents(const std::vector<HookEvent>& allEvents) {
    CategorizedEvents categorized;
    
    for (const auto& event : allEvents) {
        // DOM Manipulation
        if (isDomManipulation(event)) {
            categorized.domEvents.push_back(event);
        }
        
        // Location Change
        if (isLocationChange(event)) {
            categorized.locationEvents.push_back(event);
        }
        
        // Address Manipulation
        if (isAddrManipulation(event)) {
            categorized.addrEvents.push_back(event);
        }
        
        // Environment Detection (severity 6 이상만)
        if (isEnvironmentDetection(event) && event.severity >= 6) {
            categorized.environmentEvents.push_back(event);
        }
        
        // Crypto Operation
        if (isCryptoOperation(event)) {
            categorized.cryptoEvents.push_back(event);
        }
        
        // Critical Events (DATA_EXFILTRATION, FETCH_REQUEST)
        if (event.type == HookType::DATA_EXFILTRATION || event.type == HookType::FETCH_REQUEST) {
            categorized.criticalEvents.push_back(event);
            
            if (event.type == HookType::FETCH_REQUEST) {
                categorized.fetchEvents.push_back(event);
            }
        }
    }
    
    return categorized;
}

std::vector<HookEvent> EventProcessor::filterCriticalEvents(
    const std::vector<HookEvent>& events,
    int minSeverity) {
    
    std::vector<HookEvent> critical;
    for (const auto& event : events) {
        if (event.getSeverity() >= minSeverity) {
            critical.push_back(event);
        }
    }
    return critical;
}

std::vector<std::string> EventProcessor::detectIndirectCalls(const std::vector<HookEvent>& events) {
    std::vector<std::string> indirectCalls;
    
    for (const auto& event : events) {
        if (event.type == HookType::FUNCTION_CALL && 
            event.name.find("window[\"") != std::string::npos) {
            
            auto it = event.metadata.find("access_pattern");
            if (it != event.metadata.end()) {
                std::string pattern = JsValueToString(it->second);
                if (pattern.find("indirect_property_access") != std::string::npos) {
                    auto propIt = event.metadata.find("property");
                    if (propIt != event.metadata.end()) {
                        std::string propName = JsValueToString(propIt->second);
                        propName.erase(std::remove(propName.begin(), propName.end(), '"'), propName.end());
                        indirectCalls.push_back("window['" + propName + "']");
                    }
                }
            }
        }
    }
    
    return indirectCalls;
}

bool EventProcessor::isDomManipulation(const HookEvent& event) const {
    return event.type == HookType::DOM_MANIPULATION;
}

bool EventProcessor::isLocationChange(const HookEvent& event) const {
    return event.type == HookType::LOCATION_CHANGE;
}

bool EventProcessor::isAddrManipulation(const HookEvent& event) const {
    return event.type == HookType::ADDR_MANIPULATION;
}

bool EventProcessor::isEnvironmentDetection(const HookEvent& event) const {
    return event.type == HookType::ENVIRONMENT_DETECTION;
}


bool EventProcessor::isCryptoOperation(const HookEvent& event) const {
    if (event.type == HookType::CRYPTO_OPERATION) {
        return true;
    }
    
    // 난독화 함수도 포함
    if (event.type == HookType::FUNCTION_CALL) {
        static const std::set<std::string> obfuscationFunctions = {
            "atob", "btoa", "escape", "unescape",
            "decodeURI", "decodeURIComponent", "encodeURI", "encodeURIComponent",
            "String.fromCharCode", "parseInt"
        };
        
        return obfuscationFunctions.count(event.name) > 0 && event.name != "eval";
    }
    
    return false;
}
