#include "pch.h"
#include "EventFilter.h"
#include "../../model/JsValueVariant.h"
#include <algorithm>

std::vector<HookEvent> EventFilter::filterByType(
    const std::vector<HookEvent>& events,
    HookType type) {

    std::vector<HookEvent> filtered;
    std::copy_if(events.begin(), events.end(), std::back_inserter(filtered),
        [type](const HookEvent& event) {
            return event.type == type;
        });
    return filtered;
}

std::vector<HookEvent> EventFilter::filterByTypes(
    const std::vector<HookEvent>& events,
    const std::vector<HookType>& types) {

    std::vector<HookEvent> filtered;
    std::copy_if(events.begin(), events.end(), std::back_inserter(filtered),
        [&types](const HookEvent& event) {
            return std::find(types.begin(), types.end(), event.type) != types.end();
        });
    return filtered;
}

std::vector<HookEvent> EventFilter::filterByName(
    const std::vector<HookEvent>& events,
    const std::string& name) {

    std::vector<HookEvent> filtered;
    std::copy_if(events.begin(), events.end(), std::back_inserter(filtered),
        [&name](const HookEvent& event) {
            return event.name == name;
        });
    return filtered;
}

std::vector<HookEvent> EventFilter::filterByNamePattern(
    const std::vector<HookEvent>& events,
    const std::string& pattern) {

    std::vector<HookEvent> filtered;
    std::copy_if(events.begin(), events.end(), std::back_inserter(filtered),
        [&pattern](const HookEvent& event) {
            return event.name.find(pattern) != std::string::npos;
        });
    return filtered;
}

std::vector<HookEvent> EventFilter::filterByMinSeverity(
    const std::vector<HookEvent>& events,
    int minSeverity) {

    std::vector<HookEvent> filtered;
    std::copy_if(events.begin(), events.end(), std::back_inserter(filtered),
        [minSeverity](const HookEvent& event) {
            return event.severity >= minSeverity;
        });
    return filtered;
}

std::vector<HookEvent> EventFilter::filterByCondition(
    const std::vector<HookEvent>& events,
    std::function<bool(const HookEvent&)> condition) {

    std::vector<HookEvent> filtered;
    std::copy_if(events.begin(), events.end(), std::back_inserter(filtered), condition);
    return filtered;
}

std::vector<HookEvent> EventFilter::getCryptoOperations(
    const std::vector<HookEvent>& events) {

    return filterByType(events, HookType::CRYPTO_OPERATION);
}

bool EventFilter::hasEvalCall(const std::vector<HookEvent>& events) {
    return std::any_of(events.begin(), events.end(),
        [](const HookEvent& event) {
            return event.type == HookType::FUNCTION_CALL && event.name == "eval";
        });
}

std::vector<HookEvent> EventFilter::getIndirectPropertyAccess(
    const std::vector<HookEvent>& events) {

    std::vector<HookEvent> indirectAccess;

    for (const auto& event : events) {
        // window["eval"] 같은 간접 프로퍼티 접근 패턴 감지
        if (event.type == HookType::FUNCTION_CALL &&
            event.name.find("window[\"") != std::string::npos) {

            auto it = event.metadata.find("access_pattern");
            if (it != event.metadata.end()) {
                std::string pattern = JsValueToString(it->second);
                if (pattern == "indirect_property_access") {
                    indirectAccess.push_back(event);
                }
            }
        }
    }

    return indirectAccess;
}

std::map<HookType, std::vector<HookEvent>> EventFilter::groupByType(
    const std::vector<HookEvent>& events) {

    std::map<HookType, std::vector<HookEvent>> grouped;

    for (const auto& event : events) {
        grouped[event.type].push_back(event);
    }

    return grouped;
}

int EventFilter::getMaxSeverity(const std::vector<HookEvent>& events) {
    if (events.empty()) {
        return 0;
    }

    auto maxElement = std::max_element(events.begin(), events.end(),
        [](const HookEvent& a, const HookEvent& b) {
            return a.severity < b.severity;
        });

    return maxElement->severity;
}
