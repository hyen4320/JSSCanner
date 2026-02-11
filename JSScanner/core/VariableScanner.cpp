// VariableScanner.cpp - 전역 변수 스캐너 구현
#include "pch.h"
#include "VariableScanner.h"
#include <algorithm>

// JavaScript 키워드
const std::vector<std::string> VariableScanner::JS_KEYWORDS = {
    "function", "var", "let", "const", "if", "else", "for", "while",
    "return", "class", "new", "this", "try", "catch", "throw"
};

// 위험한 함수들
const std::vector<std::string> VariableScanner::DANGEROUS_FUNCTIONS = {
    "eval", "Function", "setTimeout", "setInterval", 
    "document.write", "innerHTML", "outerHTML",
    "fetch", "XMLHttpRequest", "navigator.clipboard",
    "atob", "btoa", "fromCharCode"
};

// 악성 패턴들
const std::vector<std::string> VariableScanner::MALICIOUS_PATTERNS = {
    "cmd /c", "cmd.exe", "powershell", "wscript", "cscript",
    ".vbs", ".bat", "CreateObject", "Execute", "WScript.Shell"
};

std::vector<ScannedVariable> VariableScanner::scanGlobalVariables(JSContext* ctx) {
    std::vector<ScannedVariable> results;
    
    // 전역 객체 가져오기
    JSValue global = JS_GetGlobalObject(ctx);
    
    // 모든 속성 이름 가져오기
    JSPropertyEnum* props;
    uint32_t prop_count;
    
    if (JS_GetOwnPropertyNames(ctx, &props, &prop_count, global, 
        JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) < 0) {
        JS_FreeValue(ctx, global);
        return results;
    }
    
    // 각 속성 검사
    for (uint32_t i = 0; i < prop_count; i++) {
        JSAtom atom = props[i].atom;
        const char* name_cstr = JS_AtomToCString(ctx, atom);
        if (!name_cstr) continue;
        
        std::string varName = name_cstr;
        JS_FreeCString(ctx, name_cstr);
        
        // 내장 객체 제외
        if (varName == "window" || varName == "document" || 
            varName == "navigator" || varName == "console" ||
            varName == "Math" || varName == "JSON" ||
            varName == "Array" || varName == "Object" ||
            varName == "String" || varName == "Number") {
            continue;
        }
        
        // 속성 값 가져오기
        JSValue val = JS_GetProperty(ctx, global, atom);
        
        // 문자열인 경우만 검사
        if (JS_IsString(val)) {
            const char* str_cstr = JS_ToCString(ctx, val);
            if (str_cstr) {
                std::string value = str_cstr;
                JS_FreeCString(ctx, str_cstr);
                
                // 최소 길이 체크 (너무 짧은 문자열 제외)
                if (value.length() >= 20) {
                    ScannedVariable scanned;
                    scanned.name = varName;
                    scanned.value = value;
                    
                    // JavaScript 코드인지 확인
                    if (looksLikeJavaScript(value)) {
                        scanned.type = "potential_js";
                        scanned.suspicionLevel = calculateSuspicionLevel(value);
                        results.push_back(scanned);
                    }
                    // Base64인지 확인
                    else if (looksLikeBase64(value) && value.length() > 100) {
                        scanned.type = "base64";
                        scanned.suspicionLevel = 5; // Base64는 중간 위험도
                        results.push_back(scanned);
                    }
                    // 악성 패턴 확인
                    else {
                        int suspicion = calculateSuspicionLevel(value);
                        if (suspicion >= 7) {
                            scanned.type = "malicious_pattern";
                            scanned.suspicionLevel = suspicion;
                            results.push_back(scanned);
                        }
                    }
                }
            }
        }
        
        JS_FreeValue(ctx, val);
    }
    
    // 정리
    for (uint32_t i = 0; i < prop_count; i++) {
        JS_FreeAtom(ctx, props[i].atom);
    }
    js_free(ctx, props);
    JS_FreeValue(ctx, global);
    
    return results;
}

bool VariableScanner::looksLikeJavaScript(const std::string& str) {
    // 1. JavaScript 키워드 포함 여부
    int keywordCount = 0;
    for (const auto& keyword : JS_KEYWORDS) {
        RE2 pattern("\\b" + keyword + "\\b");
        if (RE2::PartialMatch(str, pattern)) {
            keywordCount++;
        }
    }

    // 2개 이상의 키워드가 있으면 JavaScript일 가능성 높음
    if (keywordCount >= 2) return true;

    // 2. 함수 호출 패턴 (식별자 뒤에 괄호)
    RE2 functionCallPattern(R"([a-zA-Z_$][a-zA-Z0-9_$]*\s*\()");
    if (RE2::PartialMatch(str, functionCallPattern)) {
        // 위험한 함수 사용 확인
        for (const auto& func : DANGEROUS_FUNCTIONS) {
            if (str.find(func) != std::string::npos) {
                return true;
            }
        }
    }

    // 3. 객체 접근 패턴 (점 표기법)
    RE2 dotNotationPattern(R"([a-zA-Z_$][a-zA-Z0-9_$]*\.[a-zA-Z_$])");
    if (RE2::PartialMatch(str, dotNotationPattern)) {
        if (str.find("document.") != std::string::npos ||
            str.find("window.") != std::string::npos ||
            str.find("navigator.") != std::string::npos) {
            return true;
        }
    }

    // 4. HTML 태그 포함 (document.write에 사용)
    RE2 htmlTagPattern(R"(<[a-zA-Z][^>]*>)");
    if (RE2::PartialMatch(str, htmlTagPattern)) {
        return true;
    }

    return false;
}

bool VariableScanner::looksLikeBase64(const std::string& str) {
    if (str.length() < 4) return false;

    // Base64 문자만 포함 (A-Z, a-z, 0-9, +, /, =)
    RE2 base64Pattern("^[A-Za-z0-9+/]+=*$");
    return RE2::FullMatch(str, base64Pattern);
}

int VariableScanner::calculateSuspicionLevel(const std::string& str) {
    int level = 0;
    
    // 1. 악성 패턴 체크 (각 패턴당 +3)
    for (const auto& pattern : MALICIOUS_PATTERNS) {
        if (str.find(pattern) != std::string::npos) {
            level += 3;
        }
    }
    
    // 2. 위험한 함수 체크 (각 함수당 +2)
    for (const auto& func : DANGEROUS_FUNCTIONS) {
        if (str.find(func) != std::string::npos) {
            level += 2;
        }
    }
    
    // 3. URL 패턴 체크 (+2)
    RE2 urlPattern(R"(https?://[^\s<>\"']+)");
    if (RE2::PartialMatch(str, urlPattern)) {
        level += 2;
    }
    
    // 4. 의심스러운 문자 조합 (+1)
    if (str.find("eval") != std::string::npos ||
        str.find("Function") != std::string::npos ||
        str.find("execute") != std::string::npos) {
        level += 1;
    }
    
    // 최대 10
    return std::min(level, 10);
}
