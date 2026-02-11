#include "pch.h"
#include "ChainStep.h"

ChainStep::ChainStep(
    std::string stepId,
    std::string functionName,
    DataNode input,
    DataNode output,
    int taintLevel,
    std::map<std::string, JsValue> context
) : stepId(std::move(stepId)),
    functionName(std::move(functionName)),
    input(std::move(input)),
    output(std::move(output)),
    taintLevel(taintLevel),
    context(std::move(context))
{
    timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

std::string ChainStep::toString() const {
    std::string context_str;
    for (const auto& pair : context) {
        context_str += pair.first + ":" + JsValueToString(pair.second) + ", ";
    }
    if (!context_str.empty()) {
        context_str = context_str.substr(0, context_str.length() - 2); // Remove trailing ", "
    }

    return "ChainStep(id=" + stepId + ", func=" + functionName + ", taint=" + std::to_string(taintLevel) +
           ", input=" + input.getDataId() + ", output=" + output.getDataId() + ", context={\"" + context_str + "\"})";
}

// to_json for ChainStep
void to_json(nlohmann::json& j, const ChainStep& p) {
    j["stepId"] = p.stepId;
    j["functionName"] = p.functionName;
    j["input"] = p.input;   // Assuming DataNode has to_json
    j["output"] = p.output; // Assuming DataNode has to_json
    j["taintLevel"] = p.taintLevel;
    // context 직렬화
    nlohmann::json context_json;
    for (const auto& pair : p.context) {
        context_json[pair.first] = pair.second; // Use JsValue's to_json
    }
    j["context"] = context_json;
    j["timestamp"] = p.timestamp;
}

// from_json for ChainStep
void from_json(const nlohmann::json& j, ChainStep& p) {
    j.at("stepId").get_to(p.stepId);
    j.at("functionName").get_to(p.functionName);
    j.at("input").get_to(p.input);   // Assuming DataNode has from_json
    j.at("output").get_to(p.output); // Assuming DataNode has from_json
    j.at("taintLevel").get_to(p.taintLevel);
    // context 역직렬화
    if (j.contains("context") && j["context"].is_object()) {
        for (auto it = j["context"].begin(); it != j["context"].end(); ++it) {
            it.value().get_to(p.context[it.key()]); // Use JsValue's from_json
        }
    }
    j.at("timestamp").get_to(p.timestamp);
}

