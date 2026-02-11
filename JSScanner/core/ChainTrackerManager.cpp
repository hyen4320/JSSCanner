#include "pch.h"
#include "ChainTrackerManager.h"

ChainTrackerManager::ChainTrackerManager() {
    taintTracker = std::make_unique<TaintTracker>();
    chainDetector = std::make_unique<ChainDetector>(taintTracker.get());
}

void ChainTrackerManager::trackFunctionCall(const std::string& functionName, const std::vector<JsValue>& args, JsValue result) {
    std::map<std::string, JsValue> context;
    context["timestamp"] = static_cast<double>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    
    chainDetector->detectFunctionCall(functionName, args, result, context);
}

void ChainTrackerManager::trackVariableAssignment(const std::string& varName, JsValue value, const std::string& sourceFunction) {
    TaintedValue* taint = taintTracker->findTaintByValue(value);
    if (taint != nullptr) {
        // Safe: taintVariable stores only the valueId (string), not the pointer
        // The pointer is valid only during this call and is not stored
        taintTracker->taintVariable(varName, taint);
    }
}

bool ChainTrackerManager::isVariableTainted(const std::string& varName) const {
    return taintTracker->isVariableTainted(varName);
}

std::map<std::string, JsValue> ChainTrackerManager::generateFinalReport() const {
    std::map<std::string, JsValue> report;
    
    report["ChainAnalysis"] = chainDetector->generateReport();
    report["TaintStatistics"] = taintTracker->getStatistics();
    
    return report;
}

void ChainTrackerManager::reset() {
    taintTracker->clear();
    chainDetector->clear();
}

void ChainTrackerManager::printDebugInfo() const {
    chainDetector->printStatus();
    std::cout << "\n[TAINT TRACKER]" << std::endl;
    // TaintTracker::getStatistics() returns a map, need to print it nicely
    std::map<std::string, JsValue> stats = taintTracker->getStatistics();
    for (const auto& pair : stats) {
        std::cout << "  " << pair.first << ": ";
        std::cout << JsValueToString(pair.second) << std::endl;
    }
}
