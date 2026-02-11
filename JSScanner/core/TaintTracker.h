#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <set>
#include <memory> // For std::unique_ptr
#include <map>    // For std::map in getStatistics

#include "TaintedValue.h"

class TaintTracker {
private:
    // All tainted values (valueId -> TaintedValue)
    std::unordered_map<std::string, std::unique_ptr<TaintedValue>> taintedValues;

    // Variable name -> TaintedValue ID mapping
    std::unordered_map<std::string, std::string> variableToTaint;

    // Taint propagation graph (parent -> children valueIds)
    std::unordered_map<std::string, std::set<std::string>> propagationGraph;

    // ID generator
    int nextValueId = 1;

    // Maximum number of tainted values to prevent memory explosion
    static constexpr size_t MAX_TAINTED_VALUES = 50000;

    // Helper for recursive path tracing
    void tracePropagationPathRecursive(const std::string& valueId, std::vector<std::string>& path, std::set<std::string>& visited) const;

public:
    TaintTracker();
    ~TaintTracker() = default;

    // Create and register a new tainted value
    TaintedValue* createTaintedValue(JsValue value, const std::string& sourceFunction,
                                     int taintLevel, const std::string& reason);

    // Propagate taint to a variable
    void taintVariable(const std::string& variableName, TaintedValue* taintedValue);

    // Check if a variable is tainted
    bool isVariableTainted(const std::string& variableName) const;

    // Get taint information for a variable
    TaintedValue* getVariableTaint(const std::string& variableName) const;

    // Propagate taint from one value to a new value
    TaintedValue* propagateTaint(TaintedValue* parent, JsValue newValue, const std::string& operation);

    // Merge multiple tainted values
    TaintedValue* mergeTaints(const std::vector<TaintedValue*>& parents, JsValue mergedValue, const std::string& operation);

    // Trace the full propagation path of a specific valueId
    std::vector<std::string> tracePropagationPath(const std::string& valueId) const;

    // Find TaintedValue by its actual value (string representation)
    TaintedValue* findTaintByValue(const JsValue& value);
    const TaintedValue* findTaintByValue(const JsValue& value) const;

    // Get statistics
    std::map<std::string, JsValue> getStatistics() const;

    // Get all tainted values
    std::vector<TaintedValue*> getAllTaintedValues() const;
    
    // Get total count of tainted values
    size_t getTaintCount() const;

    // Reset all internal state
    void clear();
};
