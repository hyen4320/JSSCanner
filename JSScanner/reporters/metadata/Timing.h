#pragma once

#include <string>

// For JSON serialization (assuming nlohmann/json)
#include "../../../../Getter/Resolver/ExternalLib_json.hpp"

class Timing {
public:
    long long tookMs = 0;
    
    Timing() = default;
    Timing(long long tookMs);

    // Getters
    long long getTookMs() const { return tookMs; }

    // Setters
    void setTookMs(long long tookMs) { this->tookMs = tookMs; }

    // JSON serialization
    nlohmann::json toJson() const;
};

// nlohmann/json serialization for Timing
void to_json(nlohmann::json& j, const Timing& p);
void from_json(const nlohmann::json& j, Timing& p);
