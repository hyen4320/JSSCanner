#pragma once

#include <string>
#include <vector>
#include <set>
#include <algorithm>

class StringDeobfuscator {
public:
    static bool isSensitiveFunctionName(const std::string& str);
    static bool containsUrl(const std::string& str);
    static std::string tryXorDecode(const std::string& encoded, int key);
    static std::vector<std::string> tryCommonXorKeys(const std::string& encoded);
    static std::string decodeHex(const std::string& hex);
    static bool looksLikeHex(const std::string& str);
    static bool looksLikeBase64(const std::string& str);
    static std::string tryReverse(const std::string& str);
    
    // Clipboard hijacking detection
    static bool containsClipboardHijacking(const std::string& str);
    static bool containsMaliciousCommand(const std::string& str);
    static bool containsScriptInjection(const std::string& str);
    
    // Static pattern detection in source code
    static std::vector<std::string> extractStringLiterals(const std::string& code);
    static bool containsClipboardAPI(const std::string& code);
    static bool containsRemoteMaliciousFile(const std::string& str);

private:
    static bool isLikelyPlaintext(const std::string& str);

    static const std::set<std::string> SENSITIVE_FUNCTIONS;
    static const std::set<std::string> MALICIOUS_PATTERNS;
    static const std::set<std::string> SCRIPT_INJECTION_PATTERNS;
    // Reusing URL_PATTERN from UrlCollector or defining a local one if needed
    // For now, let's assume we can use UrlCollector's pattern or define a similar one.
    // static const std::regex URL_PATTERN; // If different from UrlCollector's
};
