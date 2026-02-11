#pragma once

#include <string>
#include <variant>
#include <vector>
#include <map>
#include <type_traits>
#include <utility>
#include <functional> // For std::recursive_wrapper
#include "../../../Getter/Resolver/ExternalLib_json.hpp" // nlohmann/json include

// Forward declare the struct to allow recursive definition
struct JsValue;

// Define JsValueVariant as a variant of basic types and recursive JsValue
using JsValueVariant = std::variant<
    std::monostate, // Represents undefined or null
    bool,           // Boolean values
    double,         // Numbers (integers and floats)
    std::string,    // Strings
    std::vector<JsValue>, // Array of JsValue
    std::map<std::string, JsValue> // Object with string keys and JsValue values
>;

// Define the recursive wrapper struct
struct JsValue {
    JsValueVariant value;

    JsValue() : value(std::monostate()) {}

    // int를 double로 자동 변환하는 생성자
    JsValue(int val) : value(static_cast<double>(val)) {}
    JsValue(unsigned int val) : value(static_cast<double>(val)) {}
    JsValue(long val) : value(static_cast<double>(val)) {}
    JsValue(unsigned long val) : value(static_cast<double>(val)) {}
    JsValue(long long val) : value(static_cast<double>(val)) {}
    JsValue(unsigned long long val) : value(static_cast<double>(val)) {}

    template<typename T, typename = std::enable_if_t<!std::is_same_v<std::decay_t<T>, JsValue> &&
                                                     !std::is_same_v<std::decay_t<T>, nlohmann::json> &&
                                                     !std::is_same_v<std::decay_t<T>, std::map<std::string, double>> &&
                                                     !std::is_integral_v<std::decay_t<T>>>>
    JsValue(T&& val) : value(std::forward<T>(val)) {}

    JsValue(const JsValue& other) = default;
    JsValue(JsValue&& other) noexcept = default;
    JsValue& operator=(const JsValue& other) = default;
    JsValue& operator=(JsValue&& other) noexcept = default;

    JsValue(const std::map<std::string, double>& val) {
        std::map<std::string, JsValue> js_map;
        for (const auto& pair : val) {
            js_map[pair.first] = JsValue(pair.second); // double을 JsValue로 변환
        }
        value = std::move(js_map);
    }

    JsValueVariant& get() noexcept { return value; }
    const JsValueVariant& get() const noexcept { return value; }
};

// Helper function to convert JsValue to string for debugging/logging
inline std::string JsValueToString(const JsValue& js_val) {
    return std::visit([](auto&& arg) -> std::string {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, std::monostate>) {
            return "[undefined/null]";
        } else if constexpr (std::is_same_v<T, bool>) {
            return arg ? "true" : "false";
        } else if constexpr (std::is_same_v<T, double>) {
            return std::to_string(arg);
        } else if constexpr (std::is_same_v<T, std::string>) {
            return "\"" + arg + "\"";
        } else if constexpr (std::is_same_v<T, std::vector<JsValue>>) {
            std::string s = "[";
            bool first = true;
            for (const auto& item : arg) {
                if (!first) s += ", ";
                s += JsValueToString(item);
                first = false;
            }
            s += "]";
            return s;
        } else if constexpr (std::is_same_v<T, std::map<std::string, JsValue>>) {
            std::string s = "{";
            bool first = true;
            for (const auto& pair : arg) {
                if (!first) s += ", ";
                s += "\"" + pair.first + "\":" + JsValueToString(pair.second);
                first = false;
            }
            s += "}";
            return s;
        }
        return "[Unknown JsValue Type]";
    }, js_val.value);
}

// nlohmann/json serialization for JsValue (forward declaration)
void to_json(nlohmann::json& j, const JsValue& p);
void from_json(const nlohmann::json& j, JsValue& p);

// Helper function to convert JsValue to nlohmann::json
inline nlohmann::json JsValueToJson(const JsValue& js_val) {
    nlohmann::json j;
    to_json(j, js_val);
    return j;
}
