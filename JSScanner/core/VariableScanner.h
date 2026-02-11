// VariableScanner.h - 전역 변수 스캐너
#pragma once
#include <string>
#include <vector>
#include <map>
#include "quickjs.h"

struct ScannedVariable {
    std::string name;
    std::string value;
    std::string type; // "potential_js", "base64", "url", "command"
    int suspicionLevel; // 1-10
};

class VariableScanner {
public:
    // QuickJS 전역 객체의 모든 변수를 스캔
    static std::vector<ScannedVariable> scanGlobalVariables(JSContext* ctx);
    
    // 문자열이 JavaScript 코드인지 판단
    static bool looksLikeJavaScript(const std::string& str);
    
    // 문자열이 Base64인지 판단
    static bool looksLikeBase64(const std::string& str);
    
    // 문자열에 위험한 패턴이 있는지 확인
    static int calculateSuspicionLevel(const std::string& str);
    
private:
    // JavaScript 키워드 목록
    static const std::vector<std::string> JS_KEYWORDS;
    
    // 위험한 함수 목록
    static const std::vector<std::string> DANGEROUS_FUNCTIONS;
    
    // 위험한 패턴 (cmd, powershell, vbs 등)
    static const std::vector<std::string> MALICIOUS_PATTERNS;
};
