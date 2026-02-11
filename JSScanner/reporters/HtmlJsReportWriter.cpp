#include "pch.h"
#include "HtmlJsReportWriter.h"

#include "../../../Getter/Resolver/ExternalLib_json.hpp"
#include <utility>

namespace htmljs_schema {
#include "../../Common/ScannerJson.hpp"
}

using ScannerReport = htmljs_schema::SCANNER_REPORT;
using ScannerDetection = htmljs_schema::Detection;
using ScannerRouteHints = htmljs_schema::RouteHints;

#include "AnalysisResponse.h"

namespace {
template <typename Container>
void AppendConvertedRange(const Container& input, std::vector<std::tstring>& output) {
    output.reserve(output.size() + input.size());
    for (const auto& item : input) {
        output.push_back(TCSFromMBS(item));
    }
}

ScannerReport BuildHtmlJsReportInternal(const AnalysisResponse& response) {
    ScannerReport report;

    std::string taskId = response.getTaskId();
    report.TaskId = TCSFromMBS(taskId);

    std::string status = response.getStatus();
    report.Status = TCSFromMBS(status);

    AppendConvertedRange(response.getExtractedFiles(), report.ExtractedFile);
    AppendConvertedRange(response.getExtractedUrls(), report.ExtractedURL);

    std::vector<ScannerDetection> DetectionsOut;
    const auto& Detections = response.getDetections();
    DetectionsOut.reserve(Detections.size());

    for (const auto& det : Detections) {
        ScannerDetection converted;
        converted.AnalysisCode = TCSFromMBS(std::string("DA"));
        converted.Name = TCSFromMBS(det.name);
        converted.Severity = TCSFromMBS(std::to_string(det.severity));

        for (const auto& [key, value] : det.features) {
            converted.features.key.push_back(TCSFromMBS(key));
            nlohmann::json jsonValue = value;
            converted.features.value.push_back(TCSFromMBS(jsonValue.dump()));
        }

        DetectionsOut.push_back(std::move(converted));
    }

    if (DetectionsOut.empty()) {
        ScannerDetection cleanDetection;
        cleanDetection.AnalysisCode = TEXT("DA");
        cleanDetection.Name = TEXT("JSScanner.Clean");
        cleanDetection.Severity = TEXT("0");
        DetectionsOut.push_back(std::move(cleanDetection));
    }

    report.DetectionVec.clear();
    if (DetectionsOut.size() > 1) {
        report.DetectionVec.assign(DetectionsOut.begin(), DetectionsOut.end() - 1);
    }
    report.detection = DetectionsOut.back();

    std::vector<ScannerRouteHints> routeHintsOut;
    const auto& hints = response.getRouteHints();
    routeHintsOut.reserve(hints.size());

    for (const auto& hint : hints) {
        ScannerRouteHints convertedHint;
        convertedHint.RouteHints.clear();
        convertedHint.key.clear();
        convertedHint.value.clear();

        if (!hint.target.empty()) {
            std::tstring value = TCSFromMBS(hint.target);
            convertedHint.RouteHints[TEXT("Target")] = value;
            convertedHint.key.push_back(TEXT("Target"));
            convertedHint.value.push_back(value);
        }
        if (!hint.reason.empty()) {
            std::tstring value = TCSFromMBS(hint.reason);
            convertedHint.RouteHints[TEXT("Reason")] = value;
            convertedHint.key.push_back(TEXT("Reason"));
            convertedHint.value.push_back(value);
        }
        if (!hint.triggers.empty()) {
            nlohmann::json triggerJson = hint.triggers;
            std::tstring value = TCSFromMBS(triggerJson.dump());
            convertedHint.RouteHints[TEXT("Trigger")] = value;
            convertedHint.key.push_back(TEXT("Trigger"));
            convertedHint.value.push_back(value);
        }

        if (!convertedHint.key.empty()) {
            routeHintsOut.push_back(std::move(convertedHint));
        }
    }

    report.RouteHintsVec.clear();
    if (!routeHintsOut.empty()) {
        if (routeHintsOut.size() > 1) {
            report.RouteHintsVec.assign(routeHintsOut.begin(), routeHintsOut.end() - 1);
        } else {
            report.RouteHintsVec.clear();
        }
        report.routehints = routeHintsOut.back();
    } else {
        report.RouteHintsVec.clear();
        report.routehints.RouteHints.clear();
        report.routehints.key.clear();
        report.routehints.value.clear();
    }

    if (!response.getTimings().empty()) {
        const auto& timing = response.getTimings().front();
        report.Timing[TEXT("TookMs")] = TCSFromMBS(std::to_string(timing.getTookMs()));
    }

    const auto& version = response.getVersion();
    report.version.key.push_back(TEXT("Scanner"));
    report.version.value.push_back(TCSFromMBS(version.getScanner()));
    report.version.key.push_back(TEXT("Rules"));
    report.version.value.push_back(TCSFromMBS(version.getRules()));

    report.Errors = TCSFromMBS(response.getErrors());

    return report;
}

std::tstring GenerateHtmlJsOutputPathT(const std::string& taskId) {
    std::tstring exePath = GetFileName();
    std::tstring exeDir = ExtractDirectory(exePath);
    std::tstring outputDir = exeDir + TEXT("/scan_report");
    CreateDirectory(outputDir.c_str());

    std::tstring fileName = TCSFromMBS(taskId) + TEXT(".js.result.json");
    return outputDir + TEXT("/") + fileName;
}

bool SaveHtmlJsReportT(const ScannerReport& report,
                       const std::string& taskId,
                       std::tstring& outPath,
                       std::tstring& outErrMsg) {
    outPath = GenerateHtmlJsOutputPathT(taskId);
    std::tstring errMsg;
    if (!UTF8::WriteJsonToFile(&report, outPath, &errMsg)) {
        outErrMsg = errMsg;
        return false;
    }
    return true;
}

bool HtmlJsReportToStringT(const ScannerReport& report,
                           std::string& outJson,
                           std::tstring& outErrMsg) {
    if (!UTF8::WriteJsonToString(&report, outJson)) {
        outErrMsg = TEXT("WriteJsonToString failed");
        return false;
    }
    return true;
}

} // namespace

bool BuildHtmlJsReportJson(const AnalysisResponse& response,
                           const std::string& taskId,
                           std::string& outJsonUtf8,
                           bool saveToFile,
                           std::string* outSavedPathUtf8,
                           std::string* outErrorUtf8) {
    std::tstring err;
    std::tstring savedPath;

    try {
        ScannerReport reportForJson = BuildHtmlJsReportInternal(response);

        if (!HtmlJsReportToStringT(reportForJson, outJsonUtf8, err)) {
            if (outErrorUtf8) {
                *outErrorUtf8 = UTF8FromTCS(err);
            }
            return false;
        }
        if (saveToFile) {
            
            ScannerReport reportForFile = BuildHtmlJsReportInternal(response);

            if (!SaveHtmlJsReportT(reportForFile, taskId, savedPath, err)) {
                if (outErrorUtf8) {
                    *outErrorUtf8 = UTF8FromTCS(err);
                }
                return false;
            }
            if (outSavedPathUtf8) {
                *outSavedPathUtf8 = UTF8FromTCS(savedPath);
            }
        }

        return true;
    } catch (const std::exception& ex) {
        if (outErrorUtf8) {
            *outErrorUtf8 = ex.what();
        }
        return false;
    }
}
