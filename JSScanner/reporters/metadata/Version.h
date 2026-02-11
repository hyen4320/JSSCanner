#pragma once

#include <string>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

#include "../../../../Getter/Resolver/ExternalLib_json.hpp"

namespace htmljs_scanner {

class Version {
public:
    std::string scanner = "1.0.0";
    std::string rules;
    
    Version();
    Version(std::string scanner, std::string rules);

    const std::string& getScanner() const { return scanner; }
    const std::string& getRules() const { return rules; }

    void setScanner(std::string scanner) { this->scanner = std::move(scanner); }
    void setRules(std::string rules) { this->rules = std::move(rules); }

    nlohmann::json toJson() const;
};

}

void to_json(nlohmann::json& j, const htmljs_scanner::Version& p);
void from_json(const nlohmann::json& j, htmljs_scanner::Version& p);
