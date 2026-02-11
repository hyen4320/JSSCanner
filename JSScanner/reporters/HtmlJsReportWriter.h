#pragma once

#include <string>

class AnalysisResponse;

// Builds the CPCore-based scanner report JSON and optionally saves it to disk.
// Returns true on success. On failure, outJson may contain fallback content.
bool BuildHtmlJsReportJson(const AnalysisResponse& response,
                           const std::string& taskId,
                           std::string& outJsonUtf8,
                           bool saveToFile = true,
                           std::string* outSavedPathUtf8 = nullptr,
                           std::string* outErrorUtf8 = nullptr);
