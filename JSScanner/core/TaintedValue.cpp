#include "pch.h"
#include "TaintedValue.h"

TaintedValue::TaintedValue(
    std::string valueId,
    JsValue value,
    std::string sourceFunction,
    int taintLevel,
    std::string reason
) : valueId(std::move(valueId)),
    value(std::move(value)),
    sourceFunction(std::move(sourceFunction)),
    taintLevel(taintLevel),
    reason(std::move(reason))
{
}

void TaintedValue::addParent(const std::string& parentId) {
    parents.insert(parentId);
}

void TaintedValue::propagateTo(const std::string& varName) {
    propagatedToVariables.insert(varName);
}

std::string TaintedValue::toString() const {
    std::string str_val = JsValueToString(value);
    
    return "TaintedValue(" + valueId + ", val=" + str_val + ", src=" + sourceFunction +
           ", level=" + std::to_string(taintLevel) + ", reason=\"" + reason + "\")";
}

// to_json for TaintedValue
void to_json(nlohmann::json& j, const TaintedValue& p) {
    j["valueId"] = p.valueId;
    j["value"] = p.value; // Use JsValue's to_json
    j["sourceFunction"] = p.sourceFunction;
    j["taintLevel"] = p.taintLevel;
    j["reason"] = p.reason;
    j["parents"] = p.parents;
    j["propagatedToVariables"] = p.propagatedToVariables;
}

// from_json for TaintedValue
void from_json(const nlohmann::json& j, TaintedValue& p) {
    j.at("valueId").get_to(p.valueId);
    j.at("value").get_to(p.value); // Use JsValue's from_json
    j.at("sourceFunction").get_to(p.sourceFunction);
    j.at("taintLevel").get_to(p.taintLevel);
    j.at("reason").get_to(p.reason);
    std::vector<std::string> parents_vec;
    j.at("parents").get_to(parents_vec);
    p.parents = std::set<std::string>(parents_vec.begin(), parents_vec.end());
    std::vector<std::string> propagatedToVariables_vec;
    j.at("propagatedToVariables").get_to(propagatedToVariables_vec);
    p.propagatedToVariables = std::set<std::string>(propagatedToVariables_vec.begin(), propagatedToVariables_vec.end());
}
