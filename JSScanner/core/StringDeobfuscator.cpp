#include "pch.h"
#include "StringDeobfuscator.h"
#include "../parser/js/UrlCollector.h" // For URL_PATTERN

// Initialize static sensitive functions
const std::set<std::string> StringDeobfuscator::SENSITIVE_FUNCTIONS = {
    "fetch", "eval", "Function", "XMLHttpRequest",
    "ActiveXObject", "setTimeout", "setInterval",
    "document", "window", "location", "navigator",
    "atob", "btoa", "escape", "unescape"
};

// Malicious command patterns
const std::set<std::string> StringDeobfuscator::MALICIOUS_PATTERNS = {
    "cmd /c", "cmd.exe", "powershell", "wscript", "cscript",
    "CreateObject", "MSXML2.XMLHTTP", "WScript.Shell",
    "%temp%", "%appdata%", "$env:temp", "Invoke-Expression",
    "IEX", "DownloadString", "DownloadFile", "Start-Process"
};

// Script injection patterns
const std::set<std::string> StringDeobfuscator::SCRIPT_INJECTION_PATTERNS = {
    "Execute(", ".ResponseText", "eval(", "Function(",
    "document.write(", "innerHTML", "outerHTML",
    "setTimeout(", "setInterval("
};

bool StringDeobfuscator::isSensitiveFunctionName(const std::string& str) {
    if (str.empty()) return false;
    std::string lower_str = str;
    std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(), ::tolower);
    return SENSITIVE_FUNCTIONS.count(lower_str);
}

bool StringDeobfuscator::containsUrl(const std::string& str) {
    if (str.length() < 7) return false;
    std::string lower_str = str;
    std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(), ::tolower);
    return lower_str.rfind("http://", 0) == 0 || 
           lower_str.rfind("https://", 0) == 0 ||
           lower_str.rfind("//", 0) == 0 ||
           lower_str.find(".com") != std::string::npos ||
           lower_str.find(".org") != std::string::npos ||
           lower_str.find(".net") != std::string::npos;
}

std::string StringDeobfuscator::tryXorDecode(const std::string& encoded, int key) {
    std::string result = encoded;
    for (char& c : result) {
        c = static_cast<char>(c ^ key);
    }
    return result;
}

bool StringDeobfuscator::isLikelyPlaintext(const std::string& str) {
    if (str.empty()) return false;
    int printable = 0;
    for (char c : str) {
        if (c >= 32 && c <= 126) printable++;
    }
    double ratio = static_cast<double>(printable) / str.length();
    return ratio > 0.8;
}

std::vector<std::string> StringDeobfuscator::tryCommonXorKeys(const std::string& encoded) {
    std::vector<std::string> results;
    int commonKeys[] = {0x69, 0x42, 0xFF, 0x55, 0xAA};
    
    for (int key : commonKeys) {
        std::string decoded = tryXorDecode(encoded, key);
        if (isLikelyPlaintext(decoded)) {
            results.push_back(decoded);
        }
    }
    return results;
}

std::string StringDeobfuscator::decodeHex(const std::string& hex) {
    std::string result;
    try {
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string hexByte = hex.substr(i, 2);
            result += static_cast<char>(std::stoi(hexByte, nullptr, 16));
        }
    } catch (...) {
        return ""; // Return empty string on error
    }
    return result;
}

bool StringDeobfuscator::looksLikeHex(const std::string& str) {
    if (str.length() < 4 || str.length() % 2 != 0) {
        return false;
    }
    return std::all_of(str.begin(), str.end(), [](char c){ return std::isxdigit(c); });
}

bool StringDeobfuscator::looksLikeBase64(const std::string& str) {
    if (str.length() < 4) return false;
    // Basic check for Base64 characters and padding
    return RE2::FullMatch(str, "[A-Za-z0-9+/]+={0,2}");
}

std::string StringDeobfuscator::tryReverse(const std::string& str) {
    if (str.length() < 3) return "";
    std::string reversed_str = str;
    std::reverse(reversed_str.begin(), reversed_str.end());
    
    if (isSensitiveFunctionName(reversed_str) || containsUrl(reversed_str)) {
        return reversed_str;
    }
    return "";
}

bool StringDeobfuscator::containsClipboardHijacking(const std::string& str) {
    if (str.empty()) return false;
    
    std::string lower_str = str;
    std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(), ::tolower);
    
    // Check for clipboard API usage
    if (lower_str.find("navigator.clipboard") != std::string::npos ||
        lower_str.find("clipboard.writetext") != std::string::npos ||
        lower_str.find("clipboard.write") != std::string::npos ||
        lower_str.find("copytoclipboard") != std::string::npos) {
        
        // Check if it contains malicious commands
        for (const auto& pattern : MALICIOUS_PATTERNS) {
            std::string lower_pattern = pattern;
            std::transform(lower_pattern.begin(), lower_pattern.end(), lower_pattern.begin(), ::tolower);
            if (lower_str.find(lower_pattern) != std::string::npos) {
                return true;
            }
        }
        
        // Check for script injection
        for (const auto& pattern : SCRIPT_INJECTION_PATTERNS) {
            std::string lower_pattern = pattern;
            std::transform(lower_pattern.begin(), lower_pattern.end(), lower_pattern.begin(), ::tolower);
            if (lower_str.find(lower_pattern) != std::string::npos) {
                return true;
            }
        }
    }
    
    return false;
}

bool StringDeobfuscator::containsMaliciousCommand(const std::string& str) {
    if (str.empty()) return false;
    
    std::string lower_str = str;
    std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(), ::tolower);
    
    for (const auto& pattern : MALICIOUS_PATTERNS) {
        std::string lower_pattern = pattern;
        std::transform(lower_pattern.begin(), lower_pattern.end(), lower_pattern.begin(), ::tolower);
        if (lower_str.find(lower_pattern) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

bool StringDeobfuscator::containsScriptInjection(const std::string& str) {
    if (str.empty()) return false;
    
    std::string lower_str = str;
    std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(), ::tolower);
    
    for (const auto& pattern : SCRIPT_INJECTION_PATTERNS) {
        std::string lower_pattern = pattern;
        std::transform(lower_pattern.begin(), lower_pattern.end(), lower_pattern.begin(), ::tolower);
        if (lower_str.find(lower_pattern) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

// Extract all string literals from source code
std::vector<std::string> StringDeobfuscator::extractStringLiterals(const std::string& code) {
    std::vector<std::string> literals;

    // Match single and double quoted strings
    // This regex handles escaped quotes: ["']([^"'\\]|\\.)*["']
    RE2 stringPattern(R"(["']([^"'\\]|\\.)*["'])");

    re2::StringPiece input(code);
    std::string content;

    while (RE2::FindAndConsume(&input, stringPattern, &content)) {
        literals.push_back(content);
    }

    return literals;
}

// Check if code contains clipboard API calls
bool StringDeobfuscator::containsClipboardAPI(const std::string& code) {
    if (code.empty()) return false;
    
    std::string lower_code = code;
    std::transform(lower_code.begin(), lower_code.end(), lower_code.begin(), ::tolower);
    
    return (lower_code.find("navigator.clipboard") != std::string::npos ||
            lower_code.find("clipboard.writetext") != std::string::npos ||
            lower_code.find("clipboard.write") != std::string::npos ||
            lower_code.find("clipboard.readtext") != std::string::npos ||
            lower_code.find("clipboard.read") != std::string::npos);
}

// Check for remote malicious file patterns (URL + suspicious extension)
bool StringDeobfuscator::containsRemoteMaliciousFile(const std::string& str) {
    if (str.empty() || str.length() < 10) return false;
    
    std::string lower_str = str;
    std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(), ::tolower);
    
    // Check if contains URL
    if (lower_str.find("http://") == std::string::npos && 
        lower_str.find("https://") == std::string::npos) {
        return false;
    }
    
    // Check for dangerous file extensions
    std::vector<std::string> dangerousExts = {
        ".vbs", ".bat", ".cmd", ".exe", ".dll", ".ps1", ".scr", ".js", ".jar"
    };
    
    for (const auto& ext : dangerousExts) {
        if (lower_str.find(ext) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}
