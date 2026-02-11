#include "pch.h"
#include "AnalysisResponse.h"

AnalysisResponse::AnalysisResponse() : statusCode(0) {}

AnalysisResponse::AnalysisResponse(std::string taskId)
    : TaskId(std::move(taskId)), Status("OK"), statusCode(0) {
}

void AnalysisResponse::addExtractedFile(std::string file) {
    extractedFiles.push_back(std::move(file));
}

void AnalysisResponse::addExtractedUrl(std::string url) {
    extractedUrls.push_back(std::move(url));
}

void AnalysisResponse::addDetection(const htmljs_scanner::Detection& detection) {
    core::Log_Warn("%sAnalysisResponse::addDetection called for: %s - %s", 
                   logMsg.c_str(), detection.analysisCode.c_str(), detection.name.c_str());
    core::Log_Warn("%s  Current Detections count: %zu", logMsg.c_str(), Detections.size());
    
    auto it = std::find_if(Detections.begin(), Detections.end(),
        [&](const htmljs_scanner::Detection& d) {
            bool nameMatch = (d.name == detection.name);
            bool codeMatch = (d.analysisCode == detection.analysisCode);
            
            core::Log_Debug("%s    Comparing with existing: %s - %s (nameMatch=%s, codeMatch=%s)", 
                          logMsg.c_str(), d.analysisCode.c_str(), d.name.c_str(),
                          (nameMatch ? "true" : "false"), (codeMatch ? "true" : "false"));
            
            return nameMatch && codeMatch;
        });

    if (it != Detections.end()) {
        core::Log_Warn("%s  DUPLICATE FOUND! Merging features...", logMsg.c_str());
        for (const auto& entry : detection.features) {
            it->addFeature(entry.first, entry.second);
        }
        if (detection.severity > it->severity) {
            it->severity = detection.severity;
        }
    } else {
        core::Log_Warn("%s  NO DUPLICATE. Adding new detection. Total will be: %zu", 
                      logMsg.c_str(), Detections.size() + 1);
        Detections.push_back(detection);
    }
}

void AnalysisResponse::addRouteHint(const RouteHint& hint) {
    RouteHints.push_back(hint);
}

void AnalysisResponse::addError(std::string error) {
    errors = std::move(error);
    if (Status != "ERROR") {
        Status = "ERROR";
    }
}

void AnalysisResponse::addTaintedValue(const TaintedValue& taintedValue) {
    TaintedValues.push_back(taintedValue);
}

void AnalysisResponse::addTaintStatistic(const std::string& key, const JsValue& value) {
    TaintStatistics[key] = value;
}

nlohmann::json AnalysisResponse::toJson() const {
    // ordered_json을 사용하여 삽입 순서 보장
    nlohmann::ordered_json j;
    
    // 요구사항에 맞춘 순서로 필드 추가
    j["TaskId"] = TaskId;
    j["Status"] = Status;
    j["ExtractedFile"] = extractedFiles;
    j["ExtractedURL"] = extractedUrls;
    
    // Detection 배열을 detectionOrder로 정렬
    std::vector<htmljs_scanner::Detection> sortedDetections = Detections;
    std::stable_sort(sortedDetections.begin(), sortedDetections.end(),
        [](const htmljs_scanner::Detection& a, const htmljs_scanner::Detection& b) {
            // detectionOrder가 0이 아닌 것들만 정렬 (0은 순서 정보 없음)
            if (a.detectionOrder == 0 && b.detectionOrder == 0) return false;
            if (a.detectionOrder == 0) return false;  // a는 뒤로
            if (b.detectionOrder == 0) return true;   // b는 뒤로
            return a.detectionOrder < b.detectionOrder;
        });
    
    nlohmann::json Detections_array = nlohmann::json::array();
    for (const auto& detection : sortedDetections) {
        nlohmann::json det_json;
        to_json(det_json, detection);
        Detections_array.push_back(det_json);
    }
    j["Detection"] = Detections_array;
    
    // RouteHints 배열 변환
    nlohmann::json hints_array = nlohmann::json::array();
    for (const auto& hint : RouteHints) {
        nlohmann::json hint_json;
        to_json(hint_json, hint);
        hints_array.push_back(hint_json);
    }
    j["RouteHints"] = hints_array;
    
    // Timing은 배열이 아닌 단일 객체로 변환
    if (!Timings.empty()) {
        nlohmann::json timing_json;
        to_json(timing_json, Timings[0]);
        j["Timing"] = timing_json;
    } else {
        j["Timing"] = nlohmann::json::object();
    }
    
    // Version 객체 변환
    nlohmann::json version_json;
    to_json(version_json, version);
    j["Version"] = version_json;
    
    // TaintedValues 배열 변환
    nlohmann::json taintedValues_array = nlohmann::json::array();
    for (const auto& taintedValue : TaintedValues) {
        nlohmann::json tv_json;
        to_json(tv_json, taintedValue);
        taintedValues_array.push_back(tv_json);
    }
    j["TaintedValues"] = taintedValues_array;
    
    // TaintStatistics 객체 변환
    nlohmann::json taintStats_json = nlohmann::json::object();
    for (const auto& [key, value] : TaintStatistics) {
        taintStats_json[key] = JsValueToJson(value);
    }
    j["TaintStatistics"] = taintStats_json;
    
    j["Errors"] = errors;
    
    // ordered_json을 일반 json으로 변환하여 반환
    return nlohmann::json(j);
}

void to_json(nlohmann::json& j, const AnalysisResponse& p) {
    j = p.toJson();
}

void from_json(const nlohmann::json& j, AnalysisResponse& p) {
    p.url = j.at("url").get<std::string>();
    p.method = j.at("method").get<std::string>();
    p.requestBody = j.at("requestBody").get<std::string>();
    p.responseBody = j.at("responseBody").get<std::string>();
    p.responseHeaders = j.at("responseHeaders").get<std::string>();
    p.requestHeaders = j.at("requestHeaders").get<std::string>();
    p.mimeType = j.at("mimeType").get<std::string>();
    p.remoteAddress = j.at("remoteAddress").get<std::string>();
    p.statusCode = j.at("statusCode").get<int>();
    j.at("routeHints").get_to(p.RouteHints);
    j.at("timings").get_to(p.Timings);

}
