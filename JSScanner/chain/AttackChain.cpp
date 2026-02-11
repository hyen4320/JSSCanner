#include "pch.h"
#include "AttackChain.h"

AttackChain::AttackChain(std::string chainId)
    : chainId(std::move(chainId)) {
}

void AttackChain::addStep(const ChainStep& step) {
    steps.push_back(step);
    // Update finalSeverity with the maximum taintLevel encountered so far
    if (step.getTaintLevel() > finalSeverity) {
        finalSeverity = step.getTaintLevel();
    }
    determineChainType(); // Re-evaluate chain type after adding a step
}

void AttackChain::complete(const std::string& reason) {
    isCompleted = true;
    completionReason = reason;
}

bool AttackChain::verifyCausality() const {
    if (steps.empty()) return true; // An empty chain is vacuously causal

    for (size_t i = 0; i < steps.size() - 1; ++i) {
        const ChainStep& currentStep = steps[i];
        const ChainStep& nextStep = steps[i+1];

        // Check if the output of the current step is the input of the next step
        // This is a simplified check, might need more sophisticated logic
        if (currentStep.getOutput().getDataId() != nextStep.getInput().getParentId()) {
            // If the output of current step is not the parent of the next step's input
            // This might indicate a break in direct causality
            // More robust check: check if nextStep.getInput().value is derived from currentStep.getOutput().value
            return false;
        }
    }
    return true;
}

nlohmann::json AttackChain::toJson() const {
    nlohmann::json j;
    j["chainId"] = chainId;
    j["chainType"] = chainType;
    j["finalSeverity"] = finalSeverity;
    j["isCompleted"] = isCompleted;
    j["completionReason"] = completionReason;

    nlohmann::json steps_json = nlohmann::json::array();
    for (const auto& step : steps) {
        steps_json.push_back(step); // Assuming ChainStep has to_json
    }
    j["steps"] = steps_json;

    return j;
}

void AttackChain::determineChainType() {
    // Simple logic: if any step involves a dangerous function, it's a "Dangerous" chain
    // Otherwise, if it involves decoders, it's "Obfuscation/Decoding"
    // This can be expanded based on specific patterns
    bool hasDangerous = false;
    bool hasDecoder = false;

    for (const auto& step : steps) {
        // These sets would ideally be defined in ChainDetector or a common place
        // For now, hardcoding for demonstration
        if (step.getFunctionName() == "eval" || step.getFunctionName() == "Function" ||
            step.getFunctionName() == "setTimeout" || step.getFunctionName() == "setInterval") {
            hasDangerous = true;
        }
        if (step.getFunctionName() == "atob" || step.getFunctionName() == "btoa" ||
            step.getFunctionName() == "unescape" || step.getFunctionName() == "decodeURIComponent") {
            hasDecoder = true;
        }
    }

    if (hasDangerous) {
        chainType = "DangerousExecution";
    } else if (hasDecoder) {
        chainType = "ObfuscationAndDecoding";
    } else {
        chainType = "Unknown";
    }
}

std::string AttackChain::toString() const {
    std::stringstream ss;
    ss << "AttackChain(id=" << chainId << ", type=" << chainType << ", severity=" << finalSeverity
       << ", completed=" << (isCompleted ? "true" : "false") << ", steps=" << steps.size() << ")";
    if (isCompleted) {
        ss << ", reason=\"" << completionReason << "\"";
    }
    return ss.str();
}

// nlohmann/json serialization for AttackChain
void to_json(nlohmann::json& j, const AttackChain& p) {
    j = p.toJson();
}

void from_json(const nlohmann::json& j, AttackChain& p) {
    j.at("chainId").get_to(p.chainId);
    j.at("chainType").get_to(p.chainType);
    j.at("finalSeverity").get_to(p.finalSeverity);
    j.at("isCompleted").get_to(p.isCompleted);
    j.at("completionReason").get_to(p.completionReason);
    //j.at("steps").get_to(p.steps); // Assuming ChainStep has from_json
}
