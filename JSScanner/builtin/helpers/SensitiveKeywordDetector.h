#pragma once
#include <string>
#include <vector>

namespace SensitiveKeywordDetector {
    /**
     * 민감한 키워드 목록
     */
    extern const std::vector<std::string> kSensitiveKeywords;

    /**
     * 텍스트에서 민감한 키워드 탐지
     * @param text 검사할 텍스트
     * @param matchedKeywords 발견된 키워드 목록 (출력)
     * @return 민감한 키워드가 발견되면 true
     */
    bool detect(const std::string& text, std::string& matchedKeywords);

    /**
     * 텍스트에 민감한 키워드가 포함되어 있는지 확인
     * @param text 검사할 텍스트
     * @return 민감한 키워드가 발견되면 true
     */
    bool containsSensitiveKeyword(const std::string& text);

    /**
     * 문자열을 소문자로 변환
     * @param input 입력 문자열
     * @return 소문자로 변환된 문자열
     */
    std::string toLower(const std::string& input);
}
