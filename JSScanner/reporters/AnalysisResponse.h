#pragma once

#include <string>
#include <vector>
#include <map>
#include <utility> // For std::move
#include <algorithm> // For std::max

#include "../core/TaintedValue.h"
#include "../model/JsValueVariant.h"
#include "metadata/RouteHint.h"
#include "metadata/Timing.h"
#include "../model/Detection.h"
#include "../hooks/HookEvent.h"
#include "../chain/AttackChain.h"
#include "metadata/Version.h"
#include "../../../Getter/Resolver/ExternalLib_json.hpp"

class AnalysisResponse {
public:
    std::string TaskId;
    std::string Status = "OK"; // OK | TIMEOUT | CANCELLED | ERROR
    std::vector<std::string> extractedFiles;
    std::vector<std::string> extractedUrls;
    // Members for request/response details
    std::string url;
    std::string method;
    std::string requestBody;
    std::string responseBody;
    std::string responseHeaders;
    std::string requestHeaders;
    std::string mimeType;
    std::string remoteAddress;
    int statusCode;

    // Members for analysis results
    std::vector<RouteHint> RouteHints;
    std::vector<Timing> Timings;
    std::vector<htmljs_scanner::Detection> Detections;
    std::vector<TaintedValue> TaintedValues;
    std::map<std::string, JsValue> TaintStatistics;

    // Members for task management and general response

    htmljs_scanner::Version version;
    std::string errors;

    // Constructors
    AnalysisResponse();
    AnalysisResponse(std::string taskId);

    // Getters
    const std::string& getUrl() const { return url; }
    const std::string& getMethod() const { return method; }
    const std::string& getRequestBody() const { return requestBody; }
    const std::string& getResponseBody() const { return responseBody; }
    const std::string& getResponseHeaders() const { return responseHeaders; }
    const std::string& getRequestHeaders() const { return requestHeaders; }
    const std::string& getMimeType() const { return mimeType; }
    const std::string& getRemoteAddress() const { return remoteAddress; }
    int getStatusCode() const { return statusCode; }

    const std::vector<std::string>& getExtractedFiles() const { return extractedFiles; }
    const std::vector<std::string>& getExtractedUrls() const { return extractedUrls; }
    const htmljs_scanner::Version& getVersion() const { return version; }
    const std::string& getErrors() const { return errors; }
    
    const std::string& getTaskId() const { return TaskId; }
    const std::string& getStatus() const { return Status; }
    const std::vector<htmljs_scanner::Detection>& getDetections() const { return Detections; }
    const std::vector<RouteHint>& getRouteHints() const { return RouteHints; }
    const std::vector<Timing>& getTimings() const { return Timings; }
    const std::vector<TaintedValue>& getTaintedValues() const { return TaintedValues; }
    const std::map<std::string, JsValue>& getTaintStatistics() const { return TaintStatistics; }

    // Setters
    void setUrl(std::string url) { this->url = std::move(url); }
    void setMethod(std::string method) { this->method = std::move(method); }
    void setRequestBody(std::string requestBody) { this->requestBody = std::move(requestBody); }
    void setResponseBody(std::string responseBody) { this->responseBody = std::move(responseBody); }
    void setResponseHeaders(std::string responseHeaders) { this->responseHeaders = std::move(responseHeaders); }
    void setRequestHeaders(std::string requestHeaders) { this->requestHeaders = std::move(requestHeaders); }
    void setMimeType(std::string mimeType) { this->mimeType = std::move(mimeType); }
    void setRemoteAddress(std::string remoteAddress) { this->remoteAddress = std::move(remoteAddress); }
    void setStatusCode(int statusCode) { this->statusCode = statusCode; }
    void setRouteHints(std::vector<RouteHint> routeHints) { this->RouteHints = std::move(routeHints); }
    void setTimings(std::vector<Timing> timings) { this->Timings = std::move(timings); }
    void setDetections(std::vector<htmljs_scanner::Detection> Detections) { this->Detections = std::move(Detections); }
    void setTaintedValues(std::vector<TaintedValue> taintedValues) { this->TaintedValues = std::move(taintedValues); }
    void setTaintStatistics(std::map<std::string, JsValue> taintStatistics) { this->TaintStatistics = std::move(taintStatistics); }


    void setTaskId(std::string taskId) { this->TaskId = std::move(taskId); }
    void setStatus(std::string status) { this->Status = std::move(status); }
    void setExtractedFiles(std::vector<std::string> extractedFiles) { this->extractedFiles = std::move(extractedFiles); }
    void setExtractedUrls(std::vector<std::string> extractedUrls) { this->extractedUrls = std::move(extractedUrls); }
    void setVersion(htmljs_scanner::Version version) { this->version = std::move(version); }
    void setErrors(std::string errors) { this->errors = std::move(errors); }

    void addExtractedFile(std::string file);
    void addExtractedUrl(std::string url);
    void addDetection(const htmljs_scanner::Detection& detection);
    void addRouteHint(const RouteHint& hint);
    void addError(std::string error);
    void addTaintedValue(const TaintedValue& taintedValue);
    void addTaintStatistic(const std::string& key, const JsValue& value);

    // JSON serialization
    nlohmann::json toJson() const;
};

// nlohmann/json serialization for AnalysisResponse
void to_json(nlohmann::json& j, const AnalysisResponse& p);
void from_json(const nlohmann::json& j, AnalysisResponse& p);
