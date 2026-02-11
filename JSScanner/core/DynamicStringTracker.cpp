#include "pch.h"
#include "DynamicStringTracker.h"
#include "StringDeobfuscator.h" // Assuming this header exists for isSensitiveFunctionName and containsUrl

DynamicStringTracker::DynamicStringTracker() {
    // Constructor: nothing specific to initialize here as members are default-constructed
}

void DynamicStringTracker::trackString(const std::string& varName, const std::string& value) {
    if (varName.empty() || value.empty()) return;

    trackedStrings[varName] = value;

    // Check for sensitive function name
    if (StringDeobfuscator::isSensitiveFunctionName(value)) {
        SensitiveStringEvent event(
            varName, value, "variable_assignment",
            "Sensitive function name stored in variable"
        );
        detectedEvents.push_back(event);
        debug("[TRACKER] Sensitive function: " + varName + " = \"" + value + "\"");
    }

    // Check for URL
    if (StringDeobfuscator::containsUrl(value)) {
        SensitiveStringEvent event(
            varName, value, "url_in_variable",
            "URL stored in variable"
        );
        detectedEvents.push_back(event);
        debug("[TRACKER] URL in variable: " + varName + " = \"" + value + "\"");
    }
    
    // 🔥 새로 추가: 복잡한 난독화 패턴 감지

    // 1. 배열 재배열 패턴 감지 (예: var _0x62E8=["..."], (_0x86F2 + 0x5 - 0x4) % 0x5)
    RE2 array_shuffle_pattern(
        R"((?i)var\s+_0x[0-9a-fA-F]+\s*=\s*\[.*?\].*?\(\s*\w+\s*[+\-]\s*0x[0-9a-fA-F]+\s*[+\-]\s*0x[0-9a-fA-F]+\s*\)\s*%\s*0x[0-9a-fA-F]+)"
    );
    if (RE2::PartialMatch(value, array_shuffle_pattern)) {
        SensitiveStringEvent event(
            varName, value.substr(0, 200), "array_obfuscation",
            "Array index shuffling pattern detected - common obfuscation technique"
        );
        detectedEvents.push_back(event);
        debug("[TRACKER] Array obfuscation: " + varName);
    }
    
    // 2. 16진수 변수명 패턴 (_0xABCD 같은 변수)
    RE2 hex_var_pattern(R"((_0x[0-9a-fA-F]{3,}))");  // Added capturing group
    int hex_var_count = 0;
    re2::StringPiece input(value);
    std::string hex_match;
    while (RE2::FindAndConsume(&input, hex_var_pattern, &hex_match)) {
        hex_var_count++;
        if (hex_var_count > 3) break; // 3개 이상이면 충분
    }
    if (hex_var_count >= 3) {
        SensitiveStringEvent event(
            varName, value.substr(0, 200), "obfuscated_variables",
            "Multiple hexadecimal variable names detected (count: " + std::to_string(hex_var_count) + ")"
        );
        detectedEvents.push_back(event);
        debug("[TRACKER] Hex variable names: " + std::to_string(hex_var_count));
    }
    
    // 3. 대량의 Base64 인코딩 데이터 (1000자 이상)
    if (value.length() > 1000 && StringDeobfuscator::looksLikeBase64(value)) {
        SensitiveStringEvent event(
            varName, value.substr(0, 100) + "...", "large_encoded_data",
            "Large Base64 encoded data (" + std::to_string(value.length()) + " bytes)"
        );
        detectedEvents.push_back(event);
        debug("[TRACKER] Large Base64: " + std::to_string(value.length()) + " bytes");
    }
    
    // 4. IIFE (즉시 실행 함수) 패턴
    RE2 iife_pattern(R"((?i)\(\s*function\s*\(\s*\)\s*\{)");
    if (RE2::PartialMatch(value, iife_pattern)) {
        SensitiveStringEvent event(
            varName, value.substr(0, 200), "iife_obfuscation",
            "Immediately Invoked Function Expression (IIFE) detected"
        );
        detectedEvents.push_back(event);
        debug("[TRACKER] IIFE pattern detected");
    }
    
    // 5. 다층 디코딩 체인 (atob + TextDecoder + document.write)
    if (value.find("atob") != std::string::npos &&
        value.find("TextDecoder") != std::string::npos &&
        value.find("document.write") != std::string::npos) {
        SensitiveStringEvent event(
            varName, value.substr(0, 200), "decoding_chain_detected",
            "Multi-layer decoding chain: atob -> TextDecoder -> document.write"
        );
        detectedEvents.push_back(event);
        debug("[TRACKER] Decoding chain detected");
    }
    
    // 6. JavaScript 코드가 문자열에 포함된 경우
    if (value.length() > 100) {
        int js_keyword_count = 0;
        std::vector<std::string> js_keywords = {
            "function", "var", "let", "const", "return", 
            "document", "window", "eval", "atob"
        };
        for (const auto& keyword : js_keywords) {
            if (value.find(keyword) != std::string::npos) {
                js_keyword_count++;
            }
        }
        if (js_keyword_count >= 3) {
            SensitiveStringEvent event(
                varName, value.substr(0, 200), "javascript_code_in_variable",
                "JavaScript code stored in variable (keywords: " + std::to_string(js_keyword_count) + ")"
            );
            detectedEvents.push_back(event);
            debug("[TRACKER] JS code in variable: " + std::to_string(js_keyword_count) + " keywords");
        }
    }
    
    // 7. HTML 코드가 문자열에 포함된 경우
    RE2 html_tag_pattern(R"((?i)<(script|iframe|object|embed|form)[^>]*>)");
    if (RE2::PartialMatch(value, html_tag_pattern)) {
        SensitiveStringEvent event(
            varName, value.substr(0, 200), "html_code_in_variable",
            "Dangerous HTML tags in variable"
        );
        detectedEvents.push_back(event);
        debug("[TRACKER] Dangerous HTML in variable");
    }
    
    // 8. 안티-분석 패턴 (navigator.userAgent, window.innerWidth 체크)
    if ((value.find("navigator.userAgent") != std::string::npos ||
         value.find("navigator[") != std::string::npos) &&
        (value.find("Mobile") != std::string::npos ||
         value.find("Android") != std::string::npos ||
         value.find("iPhone") != std::string::npos)) {
        SensitiveStringEvent event(
            varName, value.substr(0, 200), "anti_analysis_detected",
            "Anti-analysis technique: Mobile device detection"
        );
        detectedEvents.push_back(event);
        debug("[TRACKER] Anti-analysis detected");
    }
    
    // 9. 악성 패턴 (ActiveXObject, WScript.Shell 등)
    std::vector<std::string> malicious_patterns = {
        "ActiveXObject", "WScript.Shell", "WScript.Exec",
        "cmd.exe", "powershell", ".Run(", "CreateObject"
    };
    for (const auto& pattern : malicious_patterns) {
        if (value.find(pattern) != std::string::npos) {
            SensitiveStringEvent event(
                varName, value.substr(0, 200), "malicious_pattern_detected",
                "Malicious pattern detected: " + pattern
            );
            detectedEvents.push_back(event);
            debug("[TRACKER] Malicious pattern: " + pattern);
            break; // 하나만 감지해도 충분
        }
    }
    
    // 10. 클립보드 하이재킹 탐지
    if (StringDeobfuscator::containsClipboardHijacking(value)) {
        SensitiveStringEvent event(
            varName, value.substr(0, 300), "clipboard_hijacking",
            "🚨 CRITICAL: Clipboard hijacking with malicious payload detected!"
        );
        detectedEvents.push_back(event);
        debug("[TRACKER] 🚨 CLIPBOARD HIJACKING DETECTED!");
    }
    
    // 11. 악성 명령어 탐지 (cmd, wscript, CreateObject 등)
    if (StringDeobfuscator::containsMaliciousCommand(value)) {
        SensitiveStringEvent event(
            varName, value.substr(0, 300), "malicious_command",
            "⚠️  Malicious system command detected (cmd/powershell/wscript)"
        );
        detectedEvents.push_back(event);
        debug("[TRACKER] ⚠️  Malicious command detected");
    }
    
    // 12. 스크립트 인젝션 탐지
    if (StringDeobfuscator::containsScriptInjection(value)) {
        SensitiveStringEvent event(
            varName, value.substr(0, 200), "script_injection",
            "Script injection pattern detected (eval/Execute/document.write)"
        );
        detectedEvents.push_back(event);
        debug("[TRACKER] Script injection pattern");
    }
}

std::string DynamicStringTracker::getTrackedString(const std::string& varName) const {
    auto it = trackedStrings.find(varName);
    if (it != trackedStrings.end()) {
        return it->second;
    }
    return ""; // Return empty string if not found
}

std::string DynamicStringTracker::resolveIndirectCall(const std::string& varName) {
    std::string value = getTrackedString(varName);

    if (!value.empty() && StringDeobfuscator::isSensitiveFunctionName(value)) {
        debug("[TRACKER] Resolved indirect call: window[" + varName + "] -> " + value);

        SensitiveStringEvent event(
            varName, value, "indirect_call",
            "Indirect function call detected: window[" + varName + "] -> " + value
        );
        detectedEvents.push_back(event);
    }

    return value;
}

const std::vector<DynamicStringTracker::SensitiveStringEvent>& DynamicStringTracker::getDetectedEvents() const {
    return detectedEvents;
}

void DynamicStringTracker::reset() {
    trackedStrings.clear();
    detectedEvents.clear();
}

void DynamicStringTracker::generateReport() const {
    if (detectedEvents.empty()) {
        debug("✅ No sensitive string events detected");
        return;
    }

    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "DYNAMIC STRING TRACKING REPORT" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    for (const auto& event : detectedEvents) {
        std::cout << "\nEvent: " << event.type << std::endl;
        std::cout << "   Variable: " << event.varName << std::endl;
        std::cout << "   Value: \"" << event.value << "\"" << std::endl;
        std::cout << "   Description: " << event.description << std::endl;
        // For timestamp, you might want to convert long long to a readable date/time string
        // For simplicity, just printing the raw timestamp here.
        std::cout << "   Timestamp: " << event.timestamp << std::endl;
    }

    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "Summary:" << std::endl;
    std::cout << "  Total Events: " << detectedEvents.size() << std::endl;
    std::cout << "  Tracked Strings: " << trackedStrings.size() << std::endl;
    std::cout << std::string(60, '=') << "\n" << std::endl;
}
