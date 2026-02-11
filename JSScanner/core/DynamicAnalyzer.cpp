#include "pch.h"
#include "DynamicAnalyzer.h"

#include "../model/JsValueVariant.h"

namespace {
std::string summarizeHookEvent(const HookEvent& event) {
    std::ostringstream oss;
    oss << HookTypeToString(event.type) << " - " << event.name;

    if (!event.args.empty()) {
        oss << '(';
        size_t maxArgs = std::min<size_t>(event.args.size(), 3);
        for (size_t i = 0; i < maxArgs; ++i) {
            if (i > 0) {
                oss << ", ";
            }
            oss << JsValueToString(event.args[i]);
        }
        if (event.args.size() > 3) {
            oss << ", ...";
        }
        oss << ')';
    }

    if (!std::holds_alternative<std::monostate>(event.result.get())) {
        oss << " -> " << JsValueToString(event.result);
    }

    if (!event.metadata.empty()) {
        oss << " | metadata=";
        bool first = true;
        for (const auto& kv : event.metadata) {
            if (!first) {
                oss << ", ";
            }
            oss << kv.first << ':' << JsValueToString(kv.second);
            first = false;
        }
    }

    return oss.str();
}
}

DynamicAnalyzer::DynamicAnalyzer() {}
DynamicAnalyzer::~DynamicAnalyzer() {}

void DynamicAnalyzer::recordEvent(const HookEvent& event) {
    // Implement FIFO policy: remove oldest events when limit reached
    if (capturedEvents.size() >= DynamicAnalyzer::MAX_CAPTURED_EVENTS) {
        // Remove oldest 10% to avoid frequent single deletions
        size_t removeCount = DynamicAnalyzer::MAX_CAPTURED_EVENTS / 10;
        capturedEvents.erase(capturedEvents.begin(), capturedEvents.begin() + removeCount);
        core::Log_Debug("%s[HOOK] Memory limit reached. Removed %zu oldest events.", 
                       logMsg.c_str(), removeCount);
    }
    
    capturedEvents.push_back(event);
    // Hook event recorded (severity: %d)
    core::Log_Debug("%s[HOOK] %s (severity: %d)", logMsg.c_str(), summarizeHookEvent(event).c_str(), event.getSeverity());
}

const std::vector<HookEvent>& DynamicAnalyzer::getHookEvents() const {
    return capturedEvents;
}

std::vector<HookEvent> DynamicAnalyzer::getEventsBySeverity(int minSeverity) const {
    std::vector<HookEvent> filteredEvents;
    for (const auto& event : capturedEvents) {
        if (event.getSeverity() >= minSeverity) {
            filteredEvents.push_back(event);
        }
    }
    return filteredEvents;
}

void DynamicAnalyzer::reset() {
    capturedEvents.clear();
    functionCallCount = 0;
}

// 함수 호출 카운터 메서드 구현
void DynamicAnalyzer::incrementFunctionCallCount() {
    functionCallCount++;
}

size_t DynamicAnalyzer::getFunctionCallCount() const {
    return functionCallCount;
}

void DynamicAnalyzer::resetFunctionCallCount() {
    functionCallCount = 0;
}
