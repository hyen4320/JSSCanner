#pragma once
#include <set>
#include <string>

/**
 * 분석 관련 상수 정의
 * ResponseGenerator 및 관련 클래스에서 사용되는 Magic Numbers와 공통 상수들
 */
namespace AnalysisConstants {

    // ==================== Severity Thresholds ====================

    /**
     * 이벤트가 relevant로 간주되는 최소 severity
     */
    constexpr int MIN_RELEVANT_SEVERITY = 5;

    /**
     * Taint 데이터가 보고서에 포함되는 최소 level
     */
    constexpr int MIN_TAINT_LEVEL = 3;

    // ==================== Chain Display Limits ====================

    /**
     * 난독화 체인 표시 최대 단계 수
     */
    constexpr int MAX_DISPLAY_STEPS = 15;

    /**
     * Attack Chain 표시 최대 단계 수
     */
    constexpr int MAX_ATTACK_CHAIN_DISPLAY = 15;

    /**
     * Crypto 체인 수집 최대 크기 (메모리 보호)
     */
    constexpr size_t MAX_CRYPTO_CHAIN_SIZE = 1000;

    // ==================== Array.join Filtering ====================

    /**
     * Array.join이 난독화로 간주되는 최소 연속 호출 횟수
     */
    constexpr int MIN_ARRAY_JOIN_COUNT = 10;

    /**
     * 연속된 동일 함수 호출을 압축 표시하는 최소 횟수 (예: "func (x5)")
     */
    constexpr int MIN_COMPRESS_COUNT = 3;

    // ==================== Operation Grouping ====================

    /**
     * Crypto 그룹 간 non-crypto 이벤트 허용 최대 개수
     */
    constexpr int MAX_NON_CRYPTO_GAP = 3;

    // ==================== Obfuscation Functions ====================

    /**
     * 난독화에 사용되는 함수 목록
     * - Base64 인코딩/디코딩
     * - URI 인코딩/디코딩
     * - 문자열 변환
     */
    inline const std::set<std::string> OBFUSCATION_FUNCTIONS = {
        "atob",
        "btoa",
        "escape",
        "unescape",
        "decodeURI",
        "decodeURIComponent",
        "encodeURI",
        "encodeURIComponent",
        "String.fromCharCode",
        "parseInt",
        "Array.join"
    };

    /**
     * Crypto 작업으로 간주되는 함수 목록 (OBFUSCATION_FUNCTIONS의 별칭)
     */
    inline const std::set<std::string>& CRYPTO_FUNCTIONS = OBFUSCATION_FUNCTIONS;

    // ==================== Detection Names ====================

    /**
     * 통합 난독화 체인 Detection 이름
     */
    inline const std::string DETECTION_OBFUSCATION_CHAINS = "JSScanner.OBFUSCATION_CHAINS";

    /**
     * Attack Chain Detection 이름
     */
    inline const std::string DETECTION_ATTACK_CHAIN = "JSScanner.ATTACK_CHAIN";

    /**
     * Dynamic Analysis 코드
     */
    inline const std::string ANALYSIS_CODE_DA = "DA";

    /**
     * Static Analysis 코드
     */
    inline const std::string ANALYSIS_CODE_SA = "SA";

    // ==================== Display Formatting ====================

    /**
     * 체인 단계 구분자
     */
    inline const std::string CHAIN_SEPARATOR = " -> ";

    /**
     * 생략된 단계 표시 포맷
     */
    inline const std::string MORE_STEPS_FORMAT = " -> ... (+{count} more steps)";

    /**
     * 총 난독화 시도 횟수 표시 포맷
     */
    inline const std::string TOTAL_ATTEMPTS_FORMAT = " (Total {count} obfuscation attempts)";

} // namespace AnalysisConstants
