#include "pch.h"
#include "UrlCollector.h"
#include <algorithm>
#include <cctype>

// 🔥 NEW: 위험한 확장자 목록
static const std::set<std::string> EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", 
    ".scr", ".pif", ".com", ".msi", ".jar", ".app",
    ".dmg", ".deb", ".rpm", ".apk", ".ipa"
};

static const std::set<std::string> SERVER_SCRIPT_EXTENSIONS = {
    ".php", ".asp", ".aspx", ".jsp", ".cgi", ".py", ".pl", ".rb"
};

// Initialize static regex patterns
const RE2 UrlCollector::URL_PATTERN(
    "(?i)"  // Case-insensitive flag
    "("  // Outer capturing group for full match
    "https?://" // http or https
    "(?:[a-zA-Z0-9-]+\\.)*" // subdomains (non-capturing)
    "[a-zA-Z0-9-]+" // domain name
    "\\.[a-zA-Z]{2,}" // top-level domain
    "(?::\\d{1,5})?" // optional port (non-capturing)
    "(?:/[\\w\\-\\.~:/?#\\[\\]@!$&'()*+,;=%]*)?" // path, query, fragment (non-capturing)
    ")"  // End outer capturing group
);

const RE2 UrlCollector::INVALID_PATTERNS(
    "org\\.example|"
    "^document\\.|"
    "^document$|"
    "^window\\.|"
    "^console\\.|"
    "^function\\(|"
    "\\.java$|\\.class$|"
    "JSString|"
    "^\\w+\\.\\w+\\("
    "@[0-9a-f]+$"
);

UrlCollector::UrlCollector() {
    // Constructor: nothing specific to initialize here
}

bool UrlCollector::startsWith(const std::string& str, const std::string& prefix) const {
    return str.size() >= prefix.size() && str.compare(0, prefix.size(), prefix) == 0;
}

void UrlCollector::addUrl(const JsValue& urlVal) {
    std::string url;
    if (std::holds_alternative<std::string>(urlVal.get())) {
        url = std::get<std::string>(urlVal.get());
    } else {
        // If not a string, convert to string representation for logging/tracking
        url = JsValueToString(urlVal);
    }

    if (url.empty()) return;
    
    // Trim whitespace
    url.erase(0, url.find_first_not_of(" \t\n\r\f\v"));
    url.erase(url.find_last_not_of(" \t\n\r\f\v") + 1);

    if (url.length() < 3) return; // Minimum length for a valid URL
    if (RE2::PartialMatch(url, INVALID_PATTERNS)) return;
    if (url.find(" ") != std::string::npos) return; // Contains space

    // Remove trailing quotes if any
    if (url.length() > 0 && (url.back() == '\'' || url.back() == '"')) {
        url.pop_back();
    }

    // Check for absolute URLs (http:// or https://)
    bool isAbsoluteUrl = startsWith(url, "http://") || startsWith(url, "https://");
    
    // Check for relative URLs (starting with /)
    bool isRelativeUrl = url.length() > 0 && url[0] == '/';
    
    // Check for protocol-relative URLs (starting with //)
    bool isProtocolRelativeUrl = startsWith(url, "//");
    
    if (isAbsoluteUrl) {
        if (url.length() < 11) return; // Minimum length for http://a.bc
        if (RE2::FullMatch(url, URL_PATTERN)) {
            extractedUrls.insert(url);
        }
    } else if (isProtocolRelativeUrl || isRelativeUrl) {
        // For relative and protocol-relative URLs, add them directly
        // These are dynamically constructed URLs that should be tracked
        extractedUrls.insert(url);
    }
}

void UrlCollector::extractUrlsFromText(const std::string& text) {
    if (text.empty()) return;

    re2::StringPiece input(text);
    std::string url;

    // 절대 URL 추출
    while (RE2::FindAndConsume(&input, URL_PATTERN, &url)) {
        addUrl(JsValue(url));
    }
    
    // 🔥 NEW: 상대 경로 및 파일 경로 추출 (특히 .apk, .exe 등)
    // 패턴: window.open("/apk/file.apk"), href="/download/malware.exe", $.post('/down')
    RE2 relative_url_pattern(R"(["'](/[a-zA-Z0-9_/.-]+)["'])");
    input = re2::StringPiece(text);
    while (RE2::FindAndConsume(&input, relative_url_pattern, &url)) {
        addUrl(JsValue(url));
    }
    
    // 🔥 NEW: 의심스러운 확장자 추가 체크 (따옴표 없이)
    RE2 suspicious_file_pattern(R"((/[a-zA-Z0-9_/.-]+\.(?:apk|exe|dll|bat|cmd|ps1|vbs|scr|msi|jar|ipa)))");
    input = re2::StringPiece(text);
    while (RE2::FindAndConsume(&input, suspicious_file_pattern, &url)) {
        addUrl(JsValue(url));
    }
}

void UrlCollector::extractUrlsFromHtmlAttributes(const std::string& content) {
    if (content.empty()) return;

    std::vector<std::string> urlAttributes = {"src", "href", "action", "data", "poster"};

    for (const std::string& attr : urlAttributes) {
        // Regex to find attribute=value pairs
        RE2 attr_pattern(attr + "\\s*=\\s*[\"']([^\"']*)[\"']");
        re2::StringPiece input(content);
        std::string url;

        while (RE2::FindAndConsume(&input, attr_pattern, &url)) {
            if (startsWith(url, "http://") || startsWith(url, "https://")) {
                addUrl(JsValue(url)); // Use JsValue wrapper
            }
        }
    }
}

const std::set<std::string>& UrlCollector::getExtractedUrls() const {
    return extractedUrls;
}

void UrlCollector::reset() {
    extractedUrls.clear();
    urlMetadataList_.clear();  // 🔥 NEW
}


// 🔥 NEW: 확장자 추출
std::string UrlCollector::extractExtension(const std::string& url) const {
    size_t queryPos = url.find('?');
    std::string path = (queryPos != std::string::npos) ? url.substr(0, queryPos) : url;
    
    size_t fragmentPos = path.find('#');
    if (fragmentPos != std::string::npos) {
        path = path.substr(0, fragmentPos);
    }
    
    size_t lastSlash = path.rfind('/');
    std::string filename = (lastSlash != std::string::npos) ? path.substr(lastSlash + 1) : path;
    
    size_t dotPos = filename.rfind('.');
    if (dotPos != std::string::npos && dotPos < filename.length() - 1) {
        std::string ext = filename.substr(dotPos);
        std::transform(ext.begin(), ext.end(), ext.begin(),
            [](unsigned char c) { return std::tolower(c); });
        return ext;
    }
    
    return "";
}

// 🔥 NEW: 의심스러운 확장자 확인
bool UrlCollector::isSuspiciousExtension(const std::string& ext) const {
    if (ext.empty()) return false;
    
    std::string lowerExt = ext;
    std::transform(lowerExt.begin(), lowerExt.end(), lowerExt.begin(),
        [](unsigned char c) { return std::tolower(c); });
    
    return EXECUTABLE_EXTENSIONS.count(lowerExt) > 0 ||
           SERVER_SCRIPT_EXTENSIONS.count(lowerExt) > 0;
}

// 🔥 NEW: 메타데이터 포함 URL 추가
void UrlCollector::addUrlWithMetadata(const std::string& url, 
                                      const std::string& source, 
                                      int line) {
    if (url.empty()) return;
    
    std::string trimmedUrl = url;
    trimmedUrl.erase(0, trimmedUrl.find_first_not_of(" \t\n\r\f\v"));
    trimmedUrl.erase(trimmedUrl.find_last_not_of(" \t\n\r\f\v") + 1);
    
    if (trimmedUrl.length() < 3) return;
    
    // 메타데이터 생성
    UrlMetadata metadata;
    metadata.url = trimmedUrl;
    metadata.source = source;
    metadata.line = line;
    metadata.extension = extractExtension(trimmedUrl);
    metadata.hasExtension = !metadata.extension.empty();
    metadata.isSuspicious = isSuspiciousExtension(metadata.extension);
    
    urlMetadataList_.push_back(metadata);
    extractedUrls.insert(trimmedUrl);  // 기존 호환성 유지
}

// 🔥 NEW: 메타데이터 리스트 반환
const std::vector<UrlMetadata>& UrlCollector::getUrlMetadataList() const {
    return urlMetadataList_;
}

// 🔥 NEW: 의심스러운 URL만 필터링
std::vector<UrlMetadata> UrlCollector::getSuspiciousUrls() const {
    std::vector<UrlMetadata> suspicious;
    for (const auto& meta : urlMetadataList_) {
        if (meta.isSuspicious) {
            suspicious.push_back(meta);
        }
    }
    return suspicious;
}
