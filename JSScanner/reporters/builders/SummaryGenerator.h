#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <sstream>

#include "../../hooks/HookEvent.h"
#include "../../chain/AttackChain.h"
#include "../../model/JsValueVariant.h"

/**
 * SummaryGenerator - 사용자 친화적 Summary 생성 전담 클래스
 * 
 * 책임:
 * - 각 Detection 타입별 Summary 메시지 생성
 * - 위협도 레벨 결정
 * - 상세 컨텍스트 정보 포함
 */
class SummaryGenerator {
public:
    SummaryGenerator() = default;
    ~SummaryGenerator() = default;

    // DOM Manipulation Summary 생성
    std::string generateDomManipulationSummary(const std::vector<HookEvent>& domEvents);

    // Location Change Summary 생성
    std::string generateLocationChangeSummary(const std::vector<HookEvent>& locationEvents);

    // Address Manipulation Summary 생성
    std::string generateAddrManipulationSummary(const std::vector<HookEvent>& addrEvents);

    // Environment Detection Summary 생성
    std::string generateEnvironmentSummary(const std::vector<HookEvent>& envEvents);

    // Crypto/Obfuscation Summary 생성
    std::string generateCryptoSummary(
        int totalChains,
        int totalObfuscations,
        int maxChainLength,
        bool hasEval,
        const std::set<std::string>& techniques);

    // Attack Chain Summary 생성
    std::string generateAttackChainSummary(const std::vector<AttackChain>& chains);

    // Static Finding Summary 생성
    std::string generateStaticFindingSummary(
        const std::string& reason,
        int findingCount,
        const std::set<std::string>& variableNames,
        const std::set<std::string>& patterns,
        const std::string& firstSnippet);

    // Fetch Request Summary 생성
    std::string generateFetchRequestSummary(const std::vector<HookEvent>& fetchEvents);

private:
    // Helper: JsValue를 문자열로 변환
    std::string convertJsValueToString(const JsValue& val) const;
    
    // Helper: 위협도 레벨 결정
    std::string determineThreatLevel(int severity) const;
};
