#include "pch.h"
#include "JsValueVariant.h"

// nlohmann/json serialization for JsValue
void to_json(nlohmann::json& j, const JsValue& p) {
    std::visit([&j](auto&& arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, std::monostate>) {
            j = nullptr; // JSON null
        } else if constexpr (std::is_same_v<T, bool>) {
            j = arg;
        } else if constexpr (std::is_same_v<T, double>) {
            j = arg;
        } else if constexpr (std::is_same_v<T, std::string>) {
            j = arg;
        } else if constexpr (std::is_same_v<T, std::vector<JsValue>>) {
            j = nlohmann::json::array();
            for (const auto& item : arg) {
                j.push_back(item); // 재귀적으로 JsValue 직렬화
            }
        } else if constexpr (std::is_same_v<T, std::map<std::string, JsValue>>) {
            j = nlohmann::json::object();
            for (const auto& pair : arg) {
                j[pair.first] = pair.second; // 재귀적으로 JsValue 직렬화
            }
        }
    }, p.value);
}

void from_json(const nlohmann::json& j, JsValue& p) {
    if (j.is_null()) {
        p.value = std::monostate();
    } else if (j.is_boolean()) {
        p.value = j.get<bool>();
    } else if (j.is_number()) {
        p.value = j.get<double>();
    } else if (j.is_string()) {
        p.value = j.get<std::string>();
    } else if (j.is_array()) {
        std::vector<JsValue> vec;
        for (const auto& item : j) {
            JsValue val;
            item.get_to(val); // 재귀적으로 JsValue 역직렬화
            vec.push_back(val);
        }
        p.value = vec;
    } else if (j.is_object()) {
        std::map<std::string, JsValue> map;
        for (auto it = j.begin(); it != j.end(); ++it) {
            JsValue val;
            it.value().get_to(val); // 재귀적으로 JsValue 역직렬화
            map[it.key()] = val;
        }
        p.value = map;
    } else {
        // 알 수 없는 타입 처리 (예: 예외 발생 또는 기본값 설정)
        p.value = std::monostate();
    }
}
