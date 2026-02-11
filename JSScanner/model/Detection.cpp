#include "pch.h"
#include "Detection.h"

void to_json(nlohmann::json& j, const htmljs_scanner::Detection& p) {
    j["AnalysisCode"] = p.analysisCode;
    j["Name"] = p.name;
    j["Severity"] = std::to_string(p.severity);
    
    nlohmann::json features_array = nlohmann::json::array();
    for (const auto& pair : p.features) {
        nlohmann::json feature_obj;
        feature_obj[pair.first] = pair.second;
        features_array.push_back(feature_obj);
    }
    j["Features"] = features_array;
    
}

void from_json(const nlohmann::json& j, htmljs_scanner::Detection& p) {
    j.at("line").get_to(p.line);
    j.at("snippet").get_to(p.snippet);
    j.at("reason").get_to(p.reason);
    j.at("analysisCode").get_to(p.analysisCode);
    j.at("name").get_to(p.name);
    j.at("severity").get_to(p.severity);
    if (j.contains("features") && j["features"].is_object()) {
        for (auto it = j["features"].begin(); it != j["features"].end(); ++it) {
            it.value().get_to(p.features[it.key()]);
        }
    }
}
