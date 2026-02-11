#include "pch.h"
#include "BackgroundImageParser.h"

// Initialize static regex pattern
const RE2 BackgroundImageParser::URL_PATTERN(R"(url\(['"]?(data:image/[^;]+;base64,[^'"]+|[^'"]+)['"]?\))");

// Helper function to get attribute value from a GumboNode (can be shared or local)
std::string BackgroundImageParser::getAttributeValue(const GumboNode* node, const std::string& attrName) const {
    if (node->type != GUMBO_NODE_ELEMENT) {
        return "";
    }
    const GumboVector* attributes = &node->v.element.attributes;
    for (unsigned int i = 0; i < attributes->length; ++i) {
        GumboAttribute* attr = static_cast<GumboAttribute*>(attributes->data[i]);
        if (attrName == attr->name) {
            return attr->value;
        }
    }
    return "";
}

// Placeholder for HTTP client functionality
std::string BackgroundImageParser::fetchUrlContent(const std::string& url) const {
    // In a real application, this would use an HTTP client library (e.g., libcurl)
    // For migration purposes, we'll just return an empty string or a mock response.
    std::cerr << "[WARN] Attempted to fetch external CSS from: " << url << " (HTTP client not implemented)" << std::endl;
    return ""; 
}

void BackgroundImageParser::printMatch(const std::string& urlContent, const std::string& sourceType) const {
    if (urlContent.rfind("data:image/", 0) == 0) { // Check if starts with "data:image/"
        std::cout << "추출된 Base64 데이터 (" << sourceType << "): " << urlContent << std::endl;
    } else {
        std::cout << "추출된 URL (" << sourceType << "): " << urlContent << std::endl;
    }
}

void BackgroundImageParser::parseInlineStyles(const GumboNode* root) {
    std::function<void(const GumboNode*)> traverse =
        [&](const GumboNode* node) {
        if (node->type == GUMBO_NODE_ELEMENT) {
            std::string style = getAttributeValue(node, "style");
            if (!style.empty()) {
                re2::StringPiece input(style);
                std::string urlContent;
                while (RE2::FindAndConsume(&input, URL_PATTERN, &urlContent)) {
                    printMatch(urlContent, "Inline Style");
                }
            }
        }
        if (node->type == GUMBO_NODE_ELEMENT || node->type == GUMBO_NODE_DOCUMENT) {
            const GumboVector* children = &node->v.element.children;
            for (unsigned int i = 0; i < children->length; ++i) {
                traverse(static_cast<const GumboNode*>(children->data[i]));
            }
        }
    };
    traverse(root);
}

void BackgroundImageParser::parseInternalStyles(const GumboNode* root) {
    std::function<void(const GumboNode*)> traverse =
        [&](const GumboNode* node) {
        if (node->type == GUMBO_NODE_ELEMENT && node->v.element.tag == GUMBO_TAG_STYLE) {
            if (node->v.element.children.length > 0) {
                GumboNode* text_node = static_cast<GumboNode*>(node->v.element.children.data[0]);
                if (text_node->type == GUMBO_NODE_TEXT || text_node->type == GUMBO_NODE_CDATA) {
                    std::string css = text_node->v.text.text;
                    re2::StringPiece input(css);
                    std::string urlContent;
                    while (RE2::FindAndConsume(&input, URL_PATTERN, &urlContent)) {
                        printMatch(urlContent, "Internal CSS");
                    }
                }
            }
        }
        if (node->type == GUMBO_NODE_ELEMENT || node->type == GUMBO_NODE_DOCUMENT) {
            const GumboVector* children = &node->v.element.children;
            for (unsigned int i = 0; i < children->length; ++i) {
                traverse(static_cast<const GumboNode*>(children->data[i]));
            }
        }
    };
    traverse(root);
}

void BackgroundImageParser::parseExternalStyles(const GumboNode* root) {
    std::set<std::string> processedUrls;

    std::function<void(const GumboNode*)> traverse =
        [&](const GumboNode* node) {
        if (node->type == GUMBO_NODE_ELEMENT && node->v.element.tag == GUMBO_TAG_LINK) {
            std::string rel = getAttributeValue(node, "rel");
            if (rel == "stylesheet") {
                std::string cssUrl = getAttributeValue(node, "href");
                // In Gumbo, abs:href is not directly available, need to resolve relative URLs
                // For simplicity, assuming absolute URLs for now or handling in fetchUrlContent

                if (!cssUrl.empty() && processedUrls.find(cssUrl) == processedUrls.end()) {
                    processedUrls.insert(cssUrl);
                    std::string cssContent = fetchUrlContent(cssUrl);
                    if (!cssContent.empty()) {
                        re2::StringPiece input(cssContent);
                        std::string urlContent;
                        while (RE2::FindAndConsume(&input, URL_PATTERN, &urlContent)) {
                            printMatch(urlContent, "External CSS");
                        }
                    }
                }
            }
        }
        if (node->type == GUMBO_NODE_ELEMENT || node->type == GUMBO_NODE_DOCUMENT) {
            const GumboVector* children = &node->v.element.children;
            for (unsigned int i = 0; i < children->length; ++i) {
                traverse(static_cast<const GumboNode*>(children->data[i]));
            }
        }
    };
    traverse(root);
}

void BackgroundImageParser::backgroundTagParser(const std::string& htmlContent) {
    GumboOutput* output = gumbo_parse(htmlContent.c_str());
    if (!output) return;

    std::cout << "\n=== Background Image URLs & Base64 Data ===" << std::endl;

    parseInlineStyles(output->root);
    parseInternalStyles(output->root);
    parseExternalStyles(output->root);

    gumbo_destroy_output(&kGumboDefaultOptions, output);
}
