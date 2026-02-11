#pragma once
#include <string>
#include <vector>
#include <map>
#include <set>
#include "JsValueVariant.h"

namespace htmljs_scanner {

struct Detection {
    int line = 0;
    std::string snippet;
    std::string reason;

    std::string analysisCode;
    std::string name;
    int severity = 0;
    std::map<std::string, JsValue> features;
    
    // 탐지 순서 추적 (0이면 순서 정보 없음)
    int detectionOrder = 0;

    void addFeature(const std::string& key, const JsValue& value) {
        features[key] = value;
    }
};

}

void to_json(nlohmann::json& j, const htmljs_scanner::Detection& p);
void from_json(const nlohmann::json& j, htmljs_scanner::Detection& p);

