#pragma once
#include "../../hooks/HookEvent.h"
#include "../../hooks/HookType.h"
#include <vector>
#include <functional>

/**
 * HookEvent 필터링 및 그룹화를 담당하는 클래스
 * ResponseGenerator의 이벤트 필터링 로직을 캡슐화
 */
class EventFilter {
public:
    /**
     * 이벤트 타입으로 필터링
     */
    static std::vector<HookEvent> filterByType(
        const std::vector<HookEvent>& events,
        HookType type);

    /**
     * 여러 이벤트 타입으로 필터링
     */
    static std::vector<HookEvent> filterByTypes(
        const std::vector<HookEvent>& events,
        const std::vector<HookType>& types);

    /**
     * 이벤트 이름으로 필터링
     */
    static std::vector<HookEvent> filterByName(
        const std::vector<HookEvent>& events,
        const std::string& name);

    /**
     * 이름 패턴으로 필터링 (contains)
     */
    static std::vector<HookEvent> filterByNamePattern(
        const std::vector<HookEvent>& events,
        const std::string& pattern);

    /**
     * Severity로 필터링 (최소값 이상)
     */
    static std::vector<HookEvent> filterByMinSeverity(
        const std::vector<HookEvent>& events,
        int minSeverity);

    /**
     * 커스텀 조건으로 필터링
     */
    static std::vector<HookEvent> filterByCondition(
        const std::vector<HookEvent>& events,
        std::function<bool(const HookEvent&)> condition);

    /**
     * CRYPTO_OPERATION 이벤트만 추출
     */
    static std::vector<HookEvent> getCryptoOperations(
        const std::vector<HookEvent>& events);

    /**
     * eval 호출이 포함되어 있는지 확인
     */
    static bool hasEvalCall(const std::vector<HookEvent>& events);

    /**
     * 간접 프로퍼티 접근 패턴 감지 (window["eval"] 같은 패턴)
     */
    static std::vector<HookEvent> getIndirectPropertyAccess(
        const std::vector<HookEvent>& events);

    /**
     * 이벤트를 타입별로 그룹화
     */
    static std::map<HookType, std::vector<HookEvent>> groupByType(
        const std::vector<HookEvent>& events);

    /**
     * 이벤트에서 최대 severity 추출
     */
    static int getMaxSeverity(const std::vector<HookEvent>& events);
};
