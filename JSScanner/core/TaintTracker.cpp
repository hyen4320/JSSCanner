#include "pch.h"
#include "TaintTracker.h"

// debug_taint 함수
static void debug_taint(const std::string& message) {
    core::Log_Debug("%s[TAINT] %s", logMsg.c_str(), message.c_str());
}

TaintTracker::TaintTracker() {
    // Constructor: members are default-initialized
}

TaintedValue* TaintTracker::createTaintedValue(JsValue value, const std::string& sourceFunction,
                                               int taintLevel, const std::string& reason) {
    // Check memory limit
    if (taintedValues.size() >= MAX_TAINTED_VALUES) {
        debug_taint("WARNING: Max tainted values reached (" + std::to_string(MAX_TAINTED_VALUES) + "). Skipping new taint.");
        return nullptr;
    }

    std::string valueId = "taint_" + std::to_string(nextValueId++);
    auto tainted = std::make_unique<TaintedValue>(valueId, std::move(value), sourceFunction, taintLevel, reason);
    TaintedValue* rawPtr = tainted.get();
    taintedValues[valueId] = std::move(tainted);

    debug_taint("Created: " + rawPtr->toString());
    return rawPtr;
}

void TaintTracker::taintVariable(const std::string& variableName, TaintedValue* taintedValue) {
    if (!taintedValue) return; // Safety check

    variableToTaint[variableName] = taintedValue->getValueId();
    taintedValue->propagateTo(variableName);

    debug_taint("Variable " + variableName + " is now tainted by " + taintedValue->getValueId());
}

bool TaintTracker::isVariableTainted(const std::string& variableName) const {
    return variableToTaint.count(variableName) > 0;
}

TaintedValue* TaintTracker::getVariableTaint(const std::string& variableName) const {
    auto it = variableToTaint.find(variableName);
    if (it != variableToTaint.end()) {
        auto taint_it = taintedValues.find(it->second);
        if (taint_it != taintedValues.end()) {
            return taint_it->second.get();
        }
    }
    return nullptr;
}

TaintedValue* TaintTracker::propagateTaint(TaintedValue* parent, JsValue newValue, const std::string& operation) {
    if (!parent) {
        debug_taint("WARNING: Attempted to propagate from null parent");
        return nullptr;
    }

    TaintedValue* child = createTaintedValue(
        std::move(newValue),
        operation + " (from " + parent->getSourceFunction() + ")",
        parent->getTaintLevel(),
        "Propagated from " + parent->getValueId()
    );

    if (child) {
        child->addParent(parent->getValueId());
        propagationGraph[parent->getValueId()].insert(child->getValueId());
        debug_taint("Propagated: " + parent->getValueId() + " -> " + child->getValueId());
    }
    return child;
}

TaintedValue* TaintTracker::mergeTaints(const std::vector<TaintedValue*>& parents, JsValue mergedValue, const std::string& operation) {
    if (parents.empty()) {
        debug_taint("WARNING: Attempted to merge empty parent list");
        return nullptr;
    }

    // Check for null parents
    for (const auto* parent : parents) {
        if (!parent) {
            debug_taint("WARNING: Null parent in merge operation");
            return nullptr;
        }
    }

    int maxTaintLevel = 1;
    if (!parents.empty()) {
        maxTaintLevel = (*std::max_element(parents.begin(), parents.end(),
            [](TaintedValue* a, TaintedValue* b) { return a->getTaintLevel() < b->getTaintLevel(); }))->getTaintLevel();
    }

    std::string sources;
    if (!parents.empty()) {
        std::stringstream ss;
        for (size_t i = 0; i < parents.size(); ++i) {
            ss << parents[i]->getSourceFunction();
            if (i < parents.size() - 1) ss << "+";
        }
        sources = ss.str();
    } else {
        sources = "unknown";
    }

    TaintedValue* merged = createTaintedValue(
        std::move(mergedValue),
        operation + " (merged from " + sources + ")",
        maxTaintLevel + 1,  // Increase severity on merge
        "Merged from multiple sources"
    );

    if (merged) {
        for (TaintedValue* parent : parents) {
            merged->addParent(parent->getValueId());
            propagationGraph[parent->getValueId()].insert(merged->getValueId());
        }
        debug_taint("Merged " + std::to_string(parents.size()) + " taints -> " + merged->getValueId());
    }
    return merged;
}

std::vector<std::string> TaintTracker::tracePropagationPath(const std::string& valueId) const {
    std::vector<std::string> path;
    std::set<std::string> visited;
    tracePropagationPathRecursive(valueId, path, visited);
    return path;
}

void TaintTracker::tracePropagationPathRecursive(const std::string& valueId, std::vector<std::string>& path, std::set<std::string>& visited) const {
    if (visited.count(valueId)) return;
    visited.insert(valueId);
    path.push_back(valueId);

    auto it = propagationGraph.find(valueId);
    if (it != propagationGraph.end()) {
        for (const std::string& child : it->second) {
            tracePropagationPathRecursive(child, path, visited);
        }
    }
}

TaintedValue* TaintTracker::findTaintByValue(const JsValue& value) {
    std::string valueStr = JsValueToString(value);
    
    for (const auto& pair : taintedValues) {
        const TaintedValue* tv = pair.second.get();
        if (JsValueToString(tv->getValue()) == valueStr) {
            return const_cast<TaintedValue*>(tv);
        }
    }
    return nullptr;
}

const TaintedValue* TaintTracker::findTaintByValue(const JsValue& value) const {
    std::string valueStr = JsValueToString(value);
    
    for (const auto& pair : taintedValues) {
        const TaintedValue* tv = pair.second.get();
        if (JsValueToString(tv->getValue()) == valueStr) {
            return tv;
        }
    }
    return nullptr;
}

std::map<std::string, JsValue> TaintTracker::getStatistics() const {
    std::map<std::string, JsValue> stats;
    stats["TotalTaintedValues"] = static_cast<double>(taintedValues.size());
    stats["TaintedVariables"] = static_cast<double>(variableToTaint.size());

    size_t propagationEdges = 0;
    for (const auto& pair : propagationGraph) {
        propagationEdges += pair.second.size();
    }
    stats["PropagationEdges"] = static_cast<double>(propagationEdges);

    std::map<int, long long> severityDistribution;
    for (const auto& pair : taintedValues) {
        severityDistribution[pair.second->getTaintLevel()]++;
    }
    
    std::map<std::string, JsValue> severityDistStats;
    for(const auto& pair : severityDistribution) {
        severityDistStats[std::to_string(pair.first)] = static_cast<double>(pair.second);
    }
    stats["SeverityDistribution"] = severityDistStats;

    return stats;
}

std::vector<TaintedValue*> TaintTracker::getAllTaintedValues() const {
    std::vector<TaintedValue*> allTaints;
    for (const auto& pair : taintedValues) {
        allTaints.push_back(pair.second.get());
    }
    return allTaints;
}

size_t TaintTracker::getTaintCount() const {
    return taintedValues.size();
}

void TaintTracker::clear() {
    taintedValues.clear();
    variableToTaint.clear();
    propagationGraph.clear();
    nextValueId = 1;
}
