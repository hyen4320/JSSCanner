#pragma once

#include <string>
#include <vector>
#include <map>
#include <numeric> // For std::accumulate
#include <algorithm> // For std::max
#include <utility> // For std::move

#include "ChainStep.h"
#include "../model/JsValueVariant.h"
#include "../../../Getter/Resolver/ExternalLib_json.hpp" // nlohmann/json include

class AttackChain {
private:
    std::string chainId;
    std::vector<ChainStep> steps;
    std::string chainType; // Determined by analysis of steps
    int finalSeverity = 0;
    bool isCompleted = false;
    std::string completionReason;

    // Helper to determine chain type based on its steps
    void determineChainType();

public:
    AttackChain(std::string chainId);

    // Add a step to the chain
    void addStep(const ChainStep& step);

    // Complete the chain with a reason
    void complete(const std::string& reason);

    // Verify causality of the chain (e.g., output of one step is input to next) 
    bool verifyCausality() const;

    // Generate a JSON-like representation of the chain
    nlohmann::json toJson() const; // Changed return type to nlohmann::json

    // Getters
    const std::string& getChainId() const { return chainId; }
    const std::vector<ChainStep>& getSteps() const { return steps; }
    const std::string& getChainType() const { return chainType; }
    int getFinalSeverity() const { return finalSeverity; }
    bool getIsCompleted() const { return isCompleted; }
    const std::string& getCompletionReason() const { return completionReason; }

    // For debugging/logging
    std::string toString() const;

    friend void from_json(const nlohmann::json& j, AttackChain& p);
};

// nlohmann/json serialization for AttackChain
void to_json(nlohmann::json& j, const AttackChain& p);
void from_json(const nlohmann::json& j, AttackChain& p);
