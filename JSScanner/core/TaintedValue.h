#pragma once

#include <string>
#include <vector>
#include <set>
#include <utility> // For std::move
#include "../model/JsValueVariant.h"
#include "../../../Getter/Resolver/ExternalLib_json.hpp" // nlohmann/json include

class TaintedValue {
public:
    std::string valueId;
    JsValue value; // Use JsValue to hold the actual JS value
    std::string sourceFunction;
    int taintLevel;
    std::string reason;
    std::set<std::string> parents;
    std::set<std::string> propagatedToVariables;

    TaintedValue(
        std::string valueId,
        JsValue value,
        std::string sourceFunction,
        int taintLevel,
        std::string reason
    );

    // Add parent value ID to the set of parents
    void addParent(const std::string& parentId);

    // Record that this tainted value propagated to a variable
    void propagateTo(const std::string& varName);

    // Getters
    const std::string& getValueId() const { return valueId; }
    const JsValue& getValue() const { return value; }
    const std::string& getSourceFunction() const { return sourceFunction; }
    int getTaintLevel() const { return taintLevel; }
    const std::string& getReason() const { return reason; }
    const std::set<std::string>& getParents() const { return parents; }
    const std::set<std::string>& getPropagatedToVariables() const { return propagatedToVariables; }

    // For debugging/logging
    std::string toString() const;
};

// nlohmann/json serialization for TaintedValue
void to_json(nlohmann::json& j, const TaintedValue& p);
void from_json(const nlohmann::json& j, TaintedValue& p);
