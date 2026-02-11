#include "pch.h"
#include "TagParser.h"

// Local helper function for startsWith
TagParser::TagParser(UrlCollector* collector)
    : urlCollector(collector) {
}

std::string TagParser::getAttributeValue(const GumboNode* node, const std::string& attrName) const {
    if (!node || node->type != GUMBO_NODE_ELEMENT) {
        return "";
    }
    
    const GumboVector* attrs = &node->v.element.attributes;
    for (unsigned int i = 0; i < attrs->length; ++i) {
        GumboAttribute* attr = static_cast<GumboAttribute*>(attrs->data[i]);
        if (attr && attrName == attr->name) {
            return attr->value ? attr->value : "";
        }
    }
    return "";
}
std::vector<std::string> TagParser::scriptTagParser(const std::string& htmlContent) {
    std::vector<std::string> findings;
    GumboOutput* output = gumbo_parse(htmlContent.c_str());
    if (!output) return findings;

    // Recursive function to find script tags
    std::function<void(GumboNode*)> findScripts = 
        [&](GumboNode* node) {
        if (node->type == GUMBO_NODE_ELEMENT && node->v.element.tag == GUMBO_TAG_SCRIPT) {
            std::string src = getAttributeValue(node, "src");
            if (!src.empty()) {
                // 🔥 FIX: 상대 경로와 절대 경로 모두 수집
                if (urlCollector) {
                    urlCollector->addUrl(JsValue(src));
                }
            } else {
                // Inline script content
                if (node->v.element.children.length > 0) {
                    GumboNode* text_node = static_cast<GumboNode*>(node->v.element.children.data[0]);
                    if (text_node->type == GUMBO_NODE_TEXT || text_node->type == GUMBO_NODE_CDATA) {
                        std::string scriptContent = text_node->v.text.text;
                        if (!scriptContent.empty()) {
                            findings.push_back(scriptContent);
                            if (urlCollector) {
                                urlCollector->extractUrlsFromText(scriptContent);
                            }
                        }
                    }
                }
            }
        }
        // Recurse for children
        if (node->type == GUMBO_NODE_ELEMENT || node->type == GUMBO_NODE_DOCUMENT) {
            const GumboVector* children = &node->v.element.children;
            for (unsigned int i = 0; i < children->length; ++i) {
                findScripts(static_cast<GumboNode*>(children->data[i]));
            }
        }
    };

    findScripts(output->root);
    gumbo_destroy_output(&kGumboDefaultOptions, output);
    return findings;
}
