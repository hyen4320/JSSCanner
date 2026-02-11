#include "pch.h"
#include "SensitiveKeywordDetector.h"

namespace SensitiveKeywordDetector {
    const std::vector<std::string> kSensitiveKeywords = {
        "password", "passwd", "pwd",
        "token", "auth", "authorization", "bearer",
        "email", "mail", "e-mail",
        "username", "user", "userid", "user_id", "uname",
        "login", "signin",
        "cookie", "session", "sessionid", "sess",
        "secret", "key", "apikey", "api_key", "access_key",
        "credit", "card", "ssn", "social",
        "form", "input", "input[type=password]",
        "document.cookie"
    };

    std::string toLower(const std::string& input) {
        std::string lower = input;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return lower;
    }

    bool detect(const std::string& text, std::string& matchedKeywords) {
        std::string lower = toLower(text);
        std::set<std::string> detected;
        for (const auto& keyword : kSensitiveKeywords) {
            if (lower.find(keyword) != std::string::npos) {
                detected.insert(keyword);
            }
        }

        if (!detected.empty()) {
            bool first = true;
            for (const auto& keyword : detected) {
                if (!first) {
                    matchedKeywords += ", ";
                }
                matchedKeywords += keyword;
                first = false;
            }
            return true;
        }
        return false;
    }

    bool containsSensitiveKeyword(const std::string& text) {
        std::string lower = toLower(text);
        for (const auto& keyword : kSensitiveKeywords) {
            if (lower.find(keyword) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
}
