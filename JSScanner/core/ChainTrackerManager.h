#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory> // For std::unique_ptr

#include "TaintTracker.h"
#include "../chain/ChainDetector.h"
#include "../model/JsValueVariant.h"

class ChainTrackerManager {
private:
    std::unique_ptr<TaintTracker> taintTracker;
    std::unique_ptr<ChainDetector> chainDetector;

public:
    ChainTrackerManager();
    ~ChainTrackerManager() = default;

    // Track function call
    void trackFunctionCall(const std::string& functionName, const std::vector<JsValue>& args, JsValue result);

    // Track variable assignment
    void trackVariableAssignment(const std::string& varName, JsValue value, const std::string& sourceFunction);

    // Check if a variable is tainted
    bool isVariableTainted(const std::string& varName) const;

    // Generate final report
    std::map<std::string, JsValue> generateFinalReport() const;

    // Reset all trackers
    void reset();

    // Print debug info
    void printDebugInfo() const;

    // Getters
    TaintTracker* getTaintTracker() const { return taintTracker.get(); }
    ChainDetector* getChainDetector() const { return chainDetector.get(); }
};
