#include "pch.h"
#include "Timing.h"

Timing::Timing(long long tookMs)
    : tookMs(tookMs) {
}

nlohmann::json Timing::toJson() const {
    nlohmann::json j;
    j["TookMs"] = tookMs;
    return j;
}

void to_json(nlohmann::json& j, const Timing& p) {
    j = p.toJson();
}

void from_json(const nlohmann::json& j, Timing& p) {
    j.at("TookMs").get_to(p.tookMs);
}
