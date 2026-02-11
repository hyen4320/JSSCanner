#pragma once
#include <string>

class UrlComparator {
public:
    // 도메인 추출
    static std::string extractDomain(const std::string& url);
    
    // 같은 도메인인지 확인
    static bool isSameDomain(const std::string& url1, const std::string& url2);
    
    // 외부 URL인지 확인
    static bool isExternalUrl(const std::string& baseUrl, const std::string& targetUrl);
    
    // 상대 경로인지 확인
    static bool isRelativePath(const std::string& url);
    
private:
    static std::string normalizeUrl(const std::string& url);
};
