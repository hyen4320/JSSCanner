#pragma once
#include "core/JSAnalyzer.h"
#include "pch.h"

class JSScanner_API CJSScanner
{
public:
	CJSScanner();
	~CJSScanner();

	CJSScanner(const CJSScanner&) = delete;
	CJSScanner& operator=(const CJSScanner&) = delete;

	void Scan(const std::string& url, int file_name);

private:
	void SaveResult(const std::string& url, const std::string& analysisJson, int file_name, double duration_ms);
	std::string GenerateResultFilename(int file_name);
	std::string GenerateResultDirectory();

	JSAnalyzer* m_pJSAnalyzer;
};
