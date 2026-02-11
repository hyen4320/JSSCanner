#include "pch.h"
#include "CryptoChainProcessor.h"
#include "../constants/AnalysisConstants.h"
#include "../../hooks/HookType.h"
#include <algorithm>
#include <sstream>

std::vector<std::string> CryptoChainProcessor::extractCryptoChain(
    const std::vector<HookEvent>& events) {

    std::vector<std::string> chain;

    for (const auto& event : events) {
        if (event.type == HookType::CRYPTO_OPERATION) {
            chain.push_back(event.name);
        }
    }

    return chain;
}

std::vector<std::string> CryptoChainProcessor::compressRepeatedFunctions(
    const std::vector<std::string>& chain) {

    if (chain.empty()) {
        return {};
    }

    std::vector<std::string> compressed;
    std::string prevFunc;
    int count = 0;

    for (const auto& func : chain) {
        if (func == prevFunc) {
            count++;
        } else {
            if (!prevFunc.empty()) {
                if (count > AnalysisConstants::MIN_COMPRESS_COUNT) {
                    compressed.push_back(prevFunc + " (x" + std::to_string(count) + ")");
                } else {
                    for (int i = 0; i < count; i++) {
                        compressed.push_back(prevFunc);
                    }
                }
            }
            prevFunc = func;
            count = 1;
        }
    }

    // 마지막 그룹 추가
    if (!prevFunc.empty()) {
        if (count > AnalysisConstants::MIN_COMPRESS_COUNT) {
            compressed.push_back(prevFunc + " (x" + std::to_string(count) + ")");
        } else {
            for (int i = 0; i < count; i++) {
                compressed.push_back(prevFunc);
            }
        }
    }

    return compressed;
}

std::string CryptoChainProcessor::buildChainString(
    const std::vector<std::string>& chain,
    int maxSteps,
    bool showTotal,
    int totalAttempts) {

    if (chain.empty()) {
        return "";
    }

    std::ostringstream chainStr;
    size_t displayCount = std::min(chain.size(), static_cast<size_t>(maxSteps));

    for (size_t i = 0; i < displayCount; ++i) {
        if (i > 0) {
            chainStr << AnalysisConstants::CHAIN_SEPARATOR;
        }
        chainStr << chain[i];
    }

    // 제한 초과 시 생략 표시
    if (chain.size() > static_cast<size_t>(maxSteps)) {
        chainStr << AnalysisConstants::CHAIN_SEPARATOR << "... (+"
                 << (chain.size() - maxSteps) << " more steps)";
    }

    // 총 시도 횟수 표시
    if (showTotal && totalAttempts > 0) {
        chainStr << " (Total " << totalAttempts << " obfuscation attempts)";
    }

    return chainStr.str();
}

std::string CryptoChainProcessor::buildCryptoChainString(
    const std::vector<std::string>& cryptoChain) {

    if (cryptoChain.empty()) {
        return "";
    }

    // 연속된 동일 함수 압축
    std::vector<std::string> compressed = compressRepeatedFunctions(cryptoChain);

    // 체인 문자열 생성 (최대 표시 단계 제한 + 총 시도 횟수)
    return buildChainString(
        compressed,
        AnalysisConstants::MAX_DISPLAY_STEPS,
        true,  // showTotal
        static_cast<int>(cryptoChain.size())  // totalAttempts
    );
}

std::string CryptoChainProcessor::determineThreatLevel(
    int chainLength,
    bool hasEval) {

    if (hasEval && chainLength >= 20) {
        return "CRITICAL";
    } else if (hasEval && chainLength >= 10) {
        return "HIGH";
    } else if (hasEval) {
        return "MEDIUM";
    } else if (chainLength >= 10) {
        return "MEDIUM";
    } else {
        return "LOW";
    }
}

std::set<std::string> CryptoChainProcessor::extractUniqueTechniques(
    const std::vector<std::string>& chain) {

    std::set<std::string> techniques;

    for (const auto& func : chain) {
        // 압축된 함수 이름에서 원본 함수명 추출 (예: "atob (x5)" -> "atob")
        size_t spacePos = func.find(' ');
        if (spacePos != std::string::npos) {
            techniques.insert(func.substr(0, spacePos));
        } else {
            techniques.insert(func);
        }
    }

    return techniques;
}

int CryptoChainProcessor::countConsecutiveArrayJoins(
    const std::vector<std::string>& chain) {

    int maxConsecutive = 0;
    int current = 0;

    for (const auto& func : chain) {
        if (func == "Array.join" || func.find("Array.join (x") == 0) {
            current++;
            maxConsecutive = std::max(maxConsecutive, current);
        } else {
            current = 0;
        }
    }

    return maxConsecutive;
}

bool CryptoChainProcessor::isArrayJoinObfuscation(
    const std::vector<std::string>& chain) {

    int consecutiveJoins = countConsecutiveArrayJoins(chain);
    return consecutiveJoins >= AnalysisConstants::MIN_ARRAY_JOIN_COUNT;
}
