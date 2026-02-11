#pragma once
#include "../../hooks/HookEvent.h"
#include <vector>
#include <string>
#include <set>

/**
 * Crypto 체인 처리 및 문자열 생성을 담당하는 클래스
 * ResponseGenerator의 난독화 체인 관련 로직을 캡슐화
 */
class CryptoChainProcessor {
public:
    /**
     * 이벤트 목록에서 crypto 함수 이름만 추출
     */
    static std::vector<std::string> extractCryptoChain(
        const std::vector<HookEvent>& events);

    /**
     * 연속된 동일 함수 호출을 압축 (예: atob, atob, atob -> "atob (x3)")
     */
    static std::vector<std::string> compressRepeatedFunctions(
        const std::vector<std::string>& chain);

    /**
     * 체인 문자열 생성 (단계 제한 포함)
     * @param chain 압축된 체인
     * @param maxSteps 최대 표시 단계 수
     * @param showTotal 총 시도 횟수 표시 여부
     * @param totalAttempts 원본 체인의 총 시도 횟수 (압축 전)
     */
    static std::string buildChainString(
        const std::vector<std::string>& chain,
        int maxSteps,
        bool showTotal = false,
        int totalAttempts = 0);

    /**
     * 완전한 crypto 체인 문자열 생성 (압축 + 제한 + 총계)
     * @param cryptoChain 원본 crypto 함수 이름 목록
     */
    static std::string buildCryptoChainString(
        const std::vector<std::string>& cryptoChain);

    /**
     * 체인 특성 기반 위협 레벨 결정
     * @param chainLength 체인 길이
     * @param hasEval eval 호출 포함 여부
     */
    static std::string determineThreatLevel(
        int chainLength,
        bool hasEval);

    /**
     * 체인에서 사용된 고유 기술 추출
     */
    static std::set<std::string> extractUniqueTechniques(
        const std::vector<std::string>& chain);

    /**
     * Array.join 연속 호출 횟수 계산
     */
    static int countConsecutiveArrayJoins(
        const std::vector<std::string>& chain);

    /**
     * Array.join이 난독화로 간주되는지 확인
     */
    static bool isArrayJoinObfuscation(
        const std::vector<std::string>& chain);
};
