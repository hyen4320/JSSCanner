#include "pch.h"
#include "core/JSAnalyzer.h"
#include "core/DynamicAnalyzer.h"
#include "core/DynamicStringTracker.h"
#include "../../Getter/Peeker/GetterData.h"

#ifdef _WIN32
#define SCANNER_EXPORT extern "C" __declspec(dllexport)
#else
#define SCANNER_EXPORT extern "C" __attribute__((visibility("default")))
#endif

SCANNER_EXPORT void Scan(const getter::GetterData* data, const char* task_id)
{
    try
    {
        std::string taskIdStr = task_id ? task_id : "0";
        
        if (!data)
        {
            Log_Error(TEXT("[Task-%s] JSScanner received null data"), TCSFromMBS(taskIdStr).c_str());
            return;
        }

        if (data->html_file_path.empty())
        {
            Log_Error(TEXT("[Task-%s] JSScanner received empty html_file_path"), TCSFromMBS(taskIdStr).c_str());
            return;
        }

        std::string scanUrl;
        if (!data->final_url.empty()) {
            scanUrl = data->final_url;
        } else if (!data->original_url.empty()) {
            scanUrl = data->original_url;
        } else if (!data->normalized_url.empty()) {
            scanUrl = data->normalized_url;
        }

        std::tstring htmlFilePath = TCSFromMBS(data->html_file_path);
        std::tstring htmlDir = ExtractDirectory(htmlFilePath);
        std::string inputPath = UTF8FromTCS(htmlDir);

        if (inputPath.empty())
        {
            Log_Error(TEXT("[Task-%s] JSScanner failed to extract directory from html_file_path"), TCSFromMBS(taskIdStr).c_str());
            return;
        }

        JSAnalyzer jsAnalyzer;
        
        if (!scanUrl.empty()) {
            jsAnalyzer.setScanTargetUrl(scanUrl);
            Log_Info(TEXT("[Task-%s] Scan target URL: %s"), TCSFromMBS(taskIdStr).c_str(), 
                     TCSFromMBS(scanUrl).c_str());
        }
        
        jsAnalyzer.analyzeFiles(inputPath, taskIdStr);
        
        Log_Info(TEXT("[Task-%s] JSScanner - Scan finished"), TCSFromMBS(taskIdStr).c_str());
    }
    catch (const std::exception& e)
    {
        core::Log_Error("JS Scanner - failed: %s", e.what());
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <file_path> [task_id] [url]" << std::endl;
        std::cerr << "  file_path: Path to HTML/JS file or directory" << std::endl;
        std::cerr << "  task_id: Task ID (optional, default: local-task-12345)" << std::endl;
        std::cerr << "  url: Scan target URL for external communication detection (optional)" << std::endl;
        std::cerr << "Example: " << argv[0] << " malware.html 1234 https://legitimate-site.com" << std::endl;
        return 1;
    }

    std::string filePath = argv[1];
    std::string taskId = (argc > 2) ? argv[2] : "local-task-12345";
    std::string scanUrl = (argc > 3) ? argv[3] : "";  // 🔥 NEW: URL argument
    bool debugMode = false;


    core::Log_Info("%s(C++) starting", logMsg.c_str());
    core::Log_Info("%sInput path: %s", logMsg.c_str(), filePath.c_str());
    core::Log_Info("%sTaskId: %s", logMsg.c_str(), taskId.c_str());
    if (!scanUrl.empty()) {
        core::Log_Info("%sScan target URL: %s", logMsg.c_str(), scanUrl.c_str());
    }

    getter::GetterData data;
    data.html_file_path = filePath;
    
    // 🔥 NEW: Set URL for external communication detection
    if (!scanUrl.empty()) {
        data.final_url = scanUrl;
        data.original_url = scanUrl;
        data.normalized_url = scanUrl;
    } else {
        data.original_url = "local-test";
        data.final_url = "local-test";
    }
    try {
        Scan(&data, taskId.c_str());
        return 0;
    }
    catch (const std::exception& e) {
        core::Log_Error("JSScanner main failed: %s" ,std::string(e.what()));
        return 1;
    }
}
