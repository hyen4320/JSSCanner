#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <utility> // For std::move

#include "../node/DataNode.h"
#include "../model/JsValueVariant.h"
#include "../../../Getter/Resolver/ExternalLib_json.hpp" // nlohmann/json include

class ChainStep {
public:
    std::string stepId;
    std::string functionName;
    DataNode input;
    DataNode output;
    int taintLevel;
    std::map<std::string, JsValue> context; // Additional context for the step
    long long timestamp; // Milliseconds since epoch

    ChainStep(
        std::string stepId,
        std::string functionName,
        DataNode input,
        DataNode output,
        int taintLevel,
        std::map<std::string, JsValue> context = {}
    );

    // Getters
    const std::string& getStepId() const { return stepId; }
    const std::string& getFunctionName() const { return functionName; }
    const DataNode& getInput() const { return input; }
    const DataNode& getOutput() const { return output; }
    int getTaintLevel() const { return taintLevel; }
    const std::map<std::string, JsValue>& getContext() const { return context; }
    long long getTimestamp() const { return timestamp; }

    // For debugging/logging
    std::string toString() const;
};

// nlohmann/json serialization for ChainStep
void to_json(nlohmann::json& j, const ChainStep& p);
void from_json(const nlohmann::json& j, ChainStep& p);
