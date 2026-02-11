#pragma once

#include <string>
#include <set>
#include <vector>
#include <utility> // For std::move
#include <re2/re2.h>

#include "../../model/JsValueVariant.h"

// 🔥 NEW: URL 메타데이터 구조체
struct UrlMetadata {
    std::string url;
    std::string extension;      // 확장자 (.exe, .php 등)
    std::string source;         // 출처 ("fetch", "xhr", "location")
    int line;                   // 코드 라인 번호
    bool hasExtension;
    bool isSuspicious;
    
    UrlMetadata() : line(0), hasExtension(false), isSuspicious(false) {}
};

class UrlCollector {
private:
    std::set<std::string> extractedUrls;
    std::vector<UrlMetadata> urlMetadataList_;  // 🔥 NEW: 메타데이터 리스트

    static const RE2 URL_PATTERN;
    static const RE2 INVALID_PATTERNS;

    // Helper to check if a string starts with a given prefix
    bool startsWith(const std::string& str, const std::string& prefix) const;
    
    // 🔥 NEW: 헬퍼 함수들
    std::string extractExtension(const std::string& url) const;
    bool isSuspiciousExtension(const std::string& ext) const;

public:
    UrlCollector();
    ~UrlCollector() = default;

    // Add a URL from JavaScript execution (supports absolute, relative, and protocol-relative URLs)
    // - Absolute URLs: http://example.com/path or https://example.com/path
    // - Relative URLs: /path/to/resource (dynamically constructed URLs in fetch, XHR, etc.)
    // - Protocol-relative URLs: //example.com/path
    void addUrl(const JsValue& urlVal);
    
    // 🔥 NEW: 메타데이터 포함 URL 추가
    void addUrlWithMetadata(const std::string& url, const std::string& source, int line = 0);
    
    void extractUrlsFromText(const std::string& text);
    void extractUrlsFromHtmlAttributes(const std::string& content);
    const std::set<std::string>& getExtractedUrls() const;
    
    // 🔥 NEW: 메타데이터 관련 메서드
    const std::vector<UrlMetadata>& getUrlMetadataList() const;
    std::vector<UrlMetadata> getSuspiciousUrls() const;
    
    void reset();
};
