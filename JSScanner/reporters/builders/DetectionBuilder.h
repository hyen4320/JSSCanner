#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>

#include "../../model/Detection.h"
#include "../../hooks/HookEvent.h"
#include "../../model/JsValueVariant.h"
#include "../../chain/AttackChain.h"

// Forward declarations
class SummaryGenerator;
class MetadataExtractor;

/**
 * DetectionBuilder - Detection 객체 생성 전담 클래스
 * 
 * 책임:
 * - 각 타입별 Detection 객체 생성
 * - Feature 추가 및 Severity 계산
 * - Detection 메타데이터 설정
 */
class DetectionBuilder {
public:
    DetectionBuilder();
    ~DetectionBuilder() = default;

    // DOM Manipulation Detection 생성
    htmljs_scanner::Detection buildDomManipulationDetection(
        const std::vector<HookEvent>& domEvents,
        const std::string& summary);

    // Location Change Detection 생성
    htmljs_scanner::Detection buildLocationChangeDetection(
        const std::vector<HookEvent>& locationEvents,
        const std::string& summary);

    // Address Manipulation Detection 생성
    htmljs_scanner::Detection buildAddrManipulationDetection(
        const std::vector<HookEvent>& addrEvents,
        const std::string& summary);

    // Environment Detection 생성
    htmljs_scanner::Detection buildEnvironmentDetection(
        const std::vector<HookEvent>& envEvents,
        const std::string& summary);

    // Crypto/Obfuscation Detection 생성
    htmljs_scanner::Detection buildCryptoDetection(
        const std::vector<HookEvent>& cryptoEvents,
        bool hasEval,
        const std::string& summary);

    // Attack Chain Detection 생성
    htmljs_scanner::Detection buildAttackChainDetection(
        const std::vector<AttackChain>& chains,
        const std::string& summary);

    // Static Finding Detection 생성
    htmljs_scanner::Detection buildStaticFindingDetection(
        const std::string& reason,
        const std::vector<htmljs_scanner::Detection>& findings,
        const std::string& summary);

    // Critical Events Detection 생성
    htmljs_scanner::Detection buildCriticalEventsDetection(
        const std::vector<HookEvent>& criticalEvents,
        const std::string& name,
        const std::string& summary);

private:
    // Helper: JsValue를 문자열로 변환
    std::string convertJsValueToString(const JsValue& val) const;

    // Helper: Severity 계산
    int calculateSeverity(const std::string& reason) const;

    // Helper: 문자열 truncate
    std::string truncateString(const std::string& str, size_t maxLen) const;
};
