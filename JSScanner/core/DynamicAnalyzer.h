#pragma once
#include <string>
#include <vector>
#include "../hooks/Hook.h"

class DynamicAnalyzer {
public:
    DynamicAnalyzer();
    ~DynamicAnalyzer();
    void recordEvent(const HookEvent& event);
    const std::vector<HookEvent>& getHookEvents() const;
    std::vector<HookEvent> getEventsBySeverity(int minSeverity) const;
    void reset();
    
    // 함수 호출 카운터 관련 메서드
    void incrementFunctionCallCount();
    size_t getFunctionCallCount() const;
    void resetFunctionCallCount();
    
private:
    std::vector<HookEvent> capturedEvents;
    size_t functionCallCount = 0;  // 전체 함수 호출 횟수 추적
    
    // Maximum events limit (prevents memory explosion)
    static constexpr size_t MAX_CAPTURED_EVENTS = 10000;
};
