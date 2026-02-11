#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <chrono>
#include <utility>
#include <algorithm>

#include "../hooks/HookType.h"
#include "../model/JsValueVariant.h"

class HookEvent {
public:
    HookType type;
    HookType hookType;  // Alias for type (backward compatibility)
    std::string name;
    std::vector<JsValue> args;
    JsValue result;
    long long timestamp; // Milliseconds since epoch
    std::map<std::string, JsValue> metadata;
    std::map<std::string, JsValue> features;  // Alias for metadata (backward compatibility)
    int severity;
    int line;  // Source line number
    std::string reason;  // Detection reason
    std::set<std::string> tags;  // Detection tags
    int status;  // 특수 상태 플래그 (0=정상, 1=1000회 이상 함수 호출 후 fetch 등)

    // Default constructor
    HookEvent();

    HookEvent(
        HookType type,
        std::string name,
        std::vector<JsValue> args,
        JsValue result,
        std::map<std::string, JsValue> metadata,
        int severity
    );

    // Getters
    HookType getType() const { return type; }
    const std::string& getName() const { return name; }
    const std::vector<JsValue>& getArgs() const { return args; }
    const JsValue& getResult() const { return result; }
    long long getTimestamp() const { return timestamp; }
    const std::map<std::string, JsValue>& getMetadata() const { return metadata; }
    int getSeverity() const { return severity; }
    int getStatus() const { return status; }

    // For debugging/logging
    std::string toString() const;

    // JSON serialization
    nlohmann::json toJson() const;
};

// nlohmann/json serialization for HookEvent
void to_json(nlohmann::json& j, const HookEvent& p);
void from_json(const nlohmann::json& j, HookEvent& p);
