#pragma once

#include <string>
#include <set>
#include <iostream>
#include <re2/re2.h>
#include "../../../../mon47-opensrc/opensrc/gumbo/include/gumbo.h"

class BackgroundImageParser {
private:
    static const RE2 URL_PATTERN;

    // Helper to extract attribute value safely (re-using from TagParser or defining locally)
    std::string getAttributeValue(const GumboNode* node, const std::string& attrName) const;

    // Helper to fetch URL content (placeholder for HTTP client)
    std::string fetchUrlContent(const std::string& url) const;

    void parseInlineStyles(const GumboNode* root);
    void parseInternalStyles(const GumboNode* root);
    void parseExternalStyles(const GumboNode* root);
    void printMatch(const std::string& urlContent, const std::string& sourceType) const;

public:
    BackgroundImageParser() = default;
    ~BackgroundImageParser() = default;

    void backgroundTagParser(const std::string& htmlContent);
};
