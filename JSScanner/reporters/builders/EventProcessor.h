#pragma once

#include <vector>
#include <map>
#include <string>

#include "../../hooks/HookEvent.h"

/**
 * EventProcessor - HookEvent 처리 및 분류 전담 클래스
 * 
 * 책임:
 * - 이벤트를 타입별로 분류
 * - 중요 이벤트 필터링
 * - 메타데이터 추출
 */
class EventProcessor {
public:
    // 분류된 이벤트 컨테이너
    struct CategorizedEvents {
        std::vector<HookEvent> domEvents;
        std::vector<HookEvent> locationEvents;
        std::vector<HookEvent> addrEvents;
        std::vector<HookEvent> environmentEvents;
        std::vector<HookEvent> cryptoEvents;
        std::vector<HookEvent> criticalEvents;
        std::vector<HookEvent> fetchEvents;
        
        bool hasDom() const { return !domEvents.empty(); }
        bool hasLocation() const { return !locationEvents.empty(); }
        bool hasAddr() const { return !addrEvents.empty(); }
        bool hasEnvironment() const { return !environmentEvents.empty(); }
        bool hasCrypto() const { return !cryptoEvents.empty(); }
        bool hasCritical() const { return !criticalEvents.empty(); }
        bool hasFetch() const { return !fetchEvents.empty(); }
    };

    EventProcessor() = default;
    ~EventProcessor() = default;

    // 이벤트를 타입별로 분류
    CategorizedEvents categorizeEvents(const std::vector<HookEvent>& allEvents);

    // 중요 이벤트만 필터링 (severity >= threshold)
    std::vector<HookEvent> filterCriticalEvents(
        const std::vector<HookEvent>& events, 
        int minSeverity = 5);

    // 간접 호출 패턴 감지
    std::vector<std::string> detectIndirectCalls(const std::vector<HookEvent>& events);

private:
    // Helper: 이벤트가 DOM 조작인지 확인
    bool isDomManipulation(const HookEvent& event) const;

    // Helper: 이벤트가 Location 변경인지 확인
    bool isLocationChange(const HookEvent& event) const;

    // Helper: 이벤트가 주소창 조작인지 확인
    bool isAddrManipulation(const HookEvent& event) const;

    // Helper: 이벤트가 환경 감지인지 확인
    bool isEnvironmentDetection(const HookEvent& event) const;

    // Helper: 이벤트가 Crypto 작업인지 확인
    bool isCryptoOperation(const HookEvent& event) const;
};
