#include "pch.h"
#include "JSScanner.h"
#include "reporters/HtmlJsReportWriter.h"

CJSScanner::CJSScanner()
{
	m_pJSAnalyzer = new JSAnalyzer();
}

CJSScanner::~CJSScanner()
{
	delete m_pJSAnalyzer;
}

void CJSScanner::Scan(const std::string& url, int file_name)
{
	Log_Info("HtmlJS Scanner - Starting scan for: %s", url.c_str());

	auto scan_start = std::chrono::steady_clock::now();

	std::string taskId = std::to_string(file_name);

	std::tstring exePath = GetFileName();
	std::tstring exeDir = ExtractDirectory(exePath);
	std::tstring htmljsDir = exeDir + TEXT("/htmljs/") + TCSFromMBS(taskId);

	std::string analysisJson = m_pJSAnalyzer->analyzeFiles(MBSFromTCS(htmljsDir), taskId);

	auto scan_end = std::chrono::steady_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::microseconds>(scan_end - scan_start);
	double duration_ms = duration.count() / 1000.0;

	Log_Info("HtmlJS Scanner - Duration: %lf ms", duration_ms);

	SaveResult(url, analysisJson, file_name, duration_ms);

	Log_Info("HtmlJS Scanner - Scan finished for: %s", url.c_str());
}

void CJSScanner::SaveResult(const std::string& url, const std::string& analysisJson, int file_name, double duration_ms)
{
	std::string resultDir = GenerateResultDirectory();
	std::string resultPath = resultDir + "/" + GenerateResultFilename(file_name);

	std::ofstream outFile(resultPath);
	if (outFile.is_open())
	{
		outFile << analysisJson;
		outFile.close();
		Log_Info("HtmlJS Scanner - Result saved: %s", resultPath.c_str());
	}
	else
	{
		Log_Error("HtmlJS Scanner - Failed to save result: %s", resultPath.c_str());
	}
}

std::string CJSScanner::GenerateResultFilename(int file_name)
{
	return std::to_string(file_name) + ".js.result.json";
}

std::string CJSScanner::GenerateResultDirectory()
{
	std::tstring exePath = GetFileName();
	std::tstring exeDir = ExtractDirectory(exePath);
	std::tstring scannerDir = exeDir + TEXT("/scanner");
	CreateDirectory(scannerDir.c_str());
	return MBSFromTCS(scannerDir);
}
