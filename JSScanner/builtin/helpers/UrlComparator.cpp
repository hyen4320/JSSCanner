#include "pch.h"
#include "UrlComparator.h"
#include <algorithm>
#include <cctype>

std::string UrlComparator::extractDomain(const std::string& url) {
    std::string domain;
    
    // http:// 또는 https:// 제거
    size_t start = 0;
    if (url.find("://") != std::string::npos) {
        start = url.find("://") + 3;
    } else if (url.substr(0, 2) == "//") {
        start = 2;
    }
    
    // 첫 번째 슬래시까지가 호스트
    size_t end = url.find('/', start);
    if (end == std::string::npos) {
        end = url.length();
    }
    
    domain = url.substr(start, end - start);
    
    // 포트 제거
    size_t portPos = domain.find(':');
    if (portPos != std::string::npos) {
        domain = domain.substr(0, portPos);
    }
    
    return domain;
}

std::string UrlComparator::normalizeUrl(const std::string& url) {
    std::string normalized = url;
    
    // 소문자로 변환
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
        [](unsigned char c) { return std::tolower(c); });
    
    // www. 제거
    size_t wwwPos = normalized.find("www.");
    if (wwwPos != std::string::npos) {
        normalized.erase(wwwPos, 4);
    }
    
    return normalized;
}

bool UrlComparator::isSameDomain(const std::string& url1, const std::string& url2) {
    std::string domain1 = normalizeUrl(extractDomain(url1));
    std::string domain2 = normalizeUrl(extractDomain(url2));
    
    return domain1 == domain2;
}

bool UrlComparator::isRelativePath(const std::string& url) {
    if (url.empty()) return false;
    
    // 절대 URL이 아닌 경우
    if (url.find("://") == std::string::npos && 
        url.substr(0, 2) != "//" &&
        (url[0] == '/' || url[0] == '.')) {
        return true;
    }
    
    return false;
}

bool UrlComparator::isExternalUrl(const std::string& baseUrl, const std::string& targetUrl) {
    // 상대 경로는 내부
    if (isRelativePath(targetUrl)) {
        return false;
    }
    
    // 프로토콜 상대 URL
    if (targetUrl.length() >= 2 && targetUrl.substr(0, 2) == "//") {
        std::string fullTarget = "https:" + targetUrl;
        return !isSameDomain(baseUrl, fullTarget);
    }
    
    // 절대 URL
    if (targetUrl.find("://") != std::string::npos) {
        return !isSameDomain(baseUrl, targetUrl);
    }
    
    return false;
}
