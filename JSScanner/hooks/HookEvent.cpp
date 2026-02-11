#include "pch.h"
#include "HookEvent.h"

// Default constructor
HookEvent::HookEvent()
    : type(HookType::FUNCTION_CALL),
      hookType(HookType::FUNCTION_CALL),
      name(""),
      args(),
      result(),
      metadata(),
      features(),
      severity(0),
      line(0),
      reason(""),
      tags(),
      status(0)  // 기본값 0 (정상)
{
    timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

HookEvent::HookEvent(
    HookType type,
    std::string name,
    std::vector<JsValue> args,
    JsValue result,
    std::map<std::string, JsValue> metadata,
    int severity
) : type(type),
    hookType(type),
    name(std::move(name)),
    args(std::move(args)),
    result(std::move(result)),
    metadata(std::move(metadata)),
    features(),
    severity(severity),
    line(0),
    reason(""),
    tags(),
    status(0)  // 기본값 0 (정상)
{
    timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

std::string HookEvent::toString() const {
    std::stringstream sb;
    sb << "[HOOK] " << HookTypeToString(type) << " - " << name << " (severity=" << severity << ")";

    if (!args.empty()) {
        sb << "(";
        for (size_t i = 0; i < (std::min)((size_t)args.size(), (size_t)3); ++i) {
            if (i > 0) sb << ", ";
            std::string argStr = JsValueToString(args[i]);
            if (argStr.length() > 50) argStr = argStr.substr(0, 50) + "...";
            sb << argStr;
        }
        if (args.size() > 3) {
            sb << ", ...";
        }
        sb << ")";
    }
        
    // Check if result is not monostate (i.e., not undefined/null)
    if (!std::holds_alternative<std::monostate>(result.get())) {
        std::string resultStr = JsValueToString(result);
        if (resultStr.length() > 100) resultStr = resultStr.substr(0, 100) + "...";
        sb << " -> " << resultStr;
    }
        
    if (!metadata.empty()) {
        sb << " | ";
        // Convert metadata map to string representation
        sb << "{";
        bool first = true;
        for (const auto& pair : metadata) {
            if (!first) sb << ", ";
            sb << "\"" << pair.first << "\":" << JsValueToString(pair.second);
            first = false;
        }
        sb << "}";
    }
        
    return sb.str();
}

nlohmann::json HookEvent::toJson() const {
    nlohmann::json j;
    j["type"] = HookTypeToString(type);
    j["name"] = name;
    
    // Convert args to JSON array
    nlohmann::json args_json = nlohmann::json::array();
    for (const auto& arg : args) {
        args_json.push_back(arg); // Use JsValue's to_json
    }
    j["args"] = args_json;

    // Convert result to JSON
    j["result"] = result; // Use JsValue's to_json

    j["timestamp"] = timestamp;
    
    // Convert metadata to JSON object
    nlohmann::json metadata_json = nlohmann::json::object();
    for (const auto& pair : metadata) {
        metadata_json[pair.first] = pair.second; // Use JsValue's to_json
    }
    j["metadata"] = metadata_json;

    j["severity"] = severity;
    j["status"] = status;  // status 필드 추가
    return j;
}

void to_json(nlohmann::json& j, const HookEvent& p) {
    j = p.toJson();
}

void from_json(const nlohmann::json& j, HookEvent& p) {
    // HookType 역직렬화 (문자열 -> enum)
    std::string type_str;
    j.at("type").get_to(type_str);
    p.type = StringToHookType(type_str); // StringToHookType 함수 사용

    j.at("name").get_to(p.name);

    // args 역직렬화 (std::vector<JsValue>)
    if (j.contains("args") && j["args"].is_array()) {
        p.args.clear();
        for (const auto& item : j["args"]) {
            JsValue val;
            item.get_to(val); // Use JsValue's from_json
            p.args.push_back(val);
        }
    }

    // result 역직렬화 (JsValue)
    j.at("result").get_to(p.result); // Use JsValue's from_json

    j.at("timestamp").get_to(p.timestamp);

    // metadata 역직렬화 (std::map<std::string, JsValue>)
    if (j.contains("metadata") && j["metadata"].is_object()) {
        p.metadata.clear();
        for (auto it = j["metadata"].begin(); it != j["metadata"].end(); ++it) {
            it.value().get_to(p.metadata[it.key()]); // Use JsValue's from_json
        }
    }

    j.at("severity").get_to(p.severity);
    
    // status 역직렬화 (옵셔널)
    if (j.contains("status")) {
        j.at("status").get_to(p.status);
    } else {
        p.status = 0;  // 기본값
    }
}
