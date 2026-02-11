#define _CRT_SECURE_NO_WARNINGS
#include "pch.h"
#include "Version.h"

namespace htmljs_scanner {

Version::Version() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm* now_tm = std::localtime(&now_c);

    std::stringstream ss;
    ss << std::put_time(now_tm, "%Y-%m-%d");
    rules = ss.str();
}

Version::Version(std::string scanner, std::string rules)
    : scanner(std::move(scanner)), rules(std::move(rules)) {
}

nlohmann::json Version::toJson() const {
    nlohmann::json j;
    j["Scanner"] = scanner;
    j["Rules"] = rules;
    return j;
}

}

void to_json(nlohmann::json& j, const htmljs_scanner::Version& p) {
    j = p.toJson();
}

void from_json(const nlohmann::json& j, htmljs_scanner::Version& p) {
    j.at("Scanner").get_to(p.scanner);
    j.at("Rules").get_to(p.rules);
}
