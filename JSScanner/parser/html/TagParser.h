#pragma once

#include <string>
#include <vector>
#include <set>
#include <memory>
#include <re2/re2.h>
#include "../../../../mon47-opensrc/opensrc/gumbo/include/gumbo.h"

#include "../js/UrlCollector.h"


class TagParser {
private:
    UrlCollector* urlCollector; // Injected dependency

    // Helper to extract attribute value safely
    std::string getAttributeValue(const GumboNode* node, const std::string& attrName) const;
public:
    TagParser(UrlCollector* collector);
    ~TagParser() = default;

   
    // Parses <script> tags for src attributes and inline JavaScript content
    std::vector<std::string> scriptTagParser(const std::string& htmlContent);
};
