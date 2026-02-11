#pragma once

#include <string>
#include <vector>
#include <map>
#include <utility> // For std::move
#include "../model/JsValueVariant.h"
#include "../../../Getter/Resolver/ExternalLib_json.hpp" // nlohmann/json include

// Forward declaration for AttackChain, as it will use DataNode
class AttackChain;

class DataNode {
public:
    std::string dataId;
    JsValue value;
    std::string type; // e.g., "STRING", "ARRAY", "ANY"
    std::string parentId; // ID of the parent DataNode, if any
    std::map<std::string, JsValue> metadata; // Additional context

    DataNode(
        std::string dataId,
        JsValue value,
        std::string type,
        std::string parentId = "",
        std::map<std::string, JsValue> metadata = {}
    );

    // Getters
    const std::string& getDataId() const { return dataId; }
    const JsValue& getValue() const { return value; }
    const std::string& getType() const { return type; }
    const std::string& getParentId() const { return parentId; }
    const std::map<std::string, JsValue>& getMetadata() const { return metadata; }

    // For debugging/logging
    std::string toString() const;
};

// nlohmann/json serialization for DataNode
void to_json(nlohmann::json& j, const DataNode& p);
void from_json(const nlohmann::json& j, DataNode& p);
