#pragma once

#include <string>
#include <vector>
#include <utility> // For std::move

// For JSON serialization (assuming nlohmann/json)
#include "../../../../Getter/Resolver/ExternalLib_json.hpp"

class RouteHint {
public:
    std::string target;
    std::string reason;
    std::vector<std::string> triggers;

    RouteHint() = default;
    RouteHint(std::string target, std::string reason);

    // Getters
    const std::string& getTarget() const { return target; }
    const std::string& getReason() const { return reason; }
    const std::vector<std::string>& getTriggers() const { return triggers; }

    // Setters
    void setTarget(std::string target) { this->target = std::move(target); }
    void setReason(std::string reason) { this->reason = std::move(reason); }
    void setTriggers(std::vector<std::string> triggers) { this->triggers = std::move(triggers); }

    // Helper methods
    void addTrigger(std::string trigger);

    // JSON serialization
    nlohmann::json toJson() const;
};

// nlohmann/json serialization for RouteHint
void to_json(nlohmann::json& j, const RouteHint& p);
void from_json(const nlohmann::json& j, RouteHint& p);
