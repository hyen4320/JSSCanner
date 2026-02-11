#include "pch.h"
#include "RouteHint.h"

RouteHint::RouteHint(std::string target, std::string reason)
    : target(std::move(target)), reason(std::move(reason)) {
}

void RouteHint::addTrigger(std::string trigger) {
    triggers.push_back(std::move(trigger));
}

nlohmann::json RouteHint::toJson() const {
    nlohmann::json j;
    j["Target"] = target;
    j["Reason"] = reason;
    j["Trigger"] = triggers;
    return j;
}

void to_json(nlohmann::json& j, const RouteHint& p) {
    j = p.toJson();
}

void from_json(const nlohmann::json& j, RouteHint& p) {
    j.at("Target").get_to(p.target);
    j.at("Reason").get_to(p.reason);
    j.at("Trigger").get_to(p.triggers);
}
