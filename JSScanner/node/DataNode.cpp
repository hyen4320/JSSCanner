#include "pch.h"
#include "DataNode.h"

DataNode::DataNode(
    std::string dataId,
    JsValue value,
    std::string type,
    std::string parentId,
    std::map<std::string, JsValue> metadata
) : dataId(std::move(dataId)),
    value(std::move(value)),
    type(std::move(type)),
    parentId(std::move(parentId)),
    metadata(std::move(metadata))
{
}

std::string DataNode::toString() const {
    std::string value_str = JsValueToString(value);

    std::string metadata_str;
    for (const auto& pair : metadata) {
        metadata_str += pair.first + ":" + JsValueToString(pair.second) + ", ";
    }
    if (!metadata_str.empty()) {
        metadata_str = metadata_str.substr(0, metadata_str.length() - 2); // Remove trailing ", "
    }

    return "DataNode(id=" + dataId + ", val=" + value_str + ", type=" + type +
           ", parent=" + parentId + ", meta={\"" + metadata_str + "\"})";
}

// to_json for DataNode
void to_json(nlohmann::json& j, const DataNode& p) {
    j["dataId"] = p.dataId;
    j["value"] = p.value; // Use JsValue's to_json
    j["type"] = p.type;
    j["parentId"] = p.parentId;
    // metadata 직렬화
    nlohmann::json metadata_json;
    for (const auto& pair : p.metadata) {
        metadata_json[pair.first] = pair.second; // Use JsValue's to_json
    }
    j["metadata"] = metadata_json;
}

// from_json for DataNode
void from_json(const nlohmann::json& j, DataNode& p) {
    j.at("dataId").get_to(p.dataId);
    j.at("value").get_to(p.value); // Use JsValue's from_json
    j.at("type").get_to(p.type);
    j.at("parentId").get_to(p.parentId);
    // metadata 역직렬화
    if (j.contains("metadata") && j["metadata"].is_object()) {
        for (auto it = j["metadata"].begin(); it != j["metadata"].end(); ++it) {
            it.value().get_to(p.metadata[it.key()]); // Use JsValue's from_json
        }
    }
}
