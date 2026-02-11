#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <iostream> // For debug logging

#include "StringDeobfuscator.h" // Include the actual header

// No need for forward declarations here, as StringDeobfuscator.h is included
// and its static methods are directly accessible.

// Define DEBUG_MODE for conditional logging, similar to Java's Main.DEBUG_MODE
// This can be controlled by a preprocessor definition or a global variable
#ifndef SCANNER_DEBUG_MODE
#define SCANNER_DEBUG_MODE true // Set to false for release builds
#endif

class DynamicStringTracker {
public:
    // Nested class for sensitive string events
    struct SensitiveStringEvent {
        std::string varName;
        std::string value;
        std::string type;
        std::string description;
        long long timestamp; // Milliseconds since epoch

        SensitiveStringEvent(std::string varName, std::string value, std::string type, std::string description)
            : varName(std::move(varName)), value(std::move(value)), type(std::move(type)), description(std::move(description)) {
            timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();
        }
    };

private:
    std::unordered_map<std::string, std::string> trackedStrings;
    std::vector<SensitiveStringEvent> detectedEvents;

    void debug(const std::string& message) const {
        if (SCANNER_DEBUG_MODE) {
            std::cerr << "[DynamicStringTracker] " << message << std::endl;
        }
    }

public:
    DynamicStringTracker();
    ~DynamicStringTracker() = default; // Default destructor

    void trackString(const std::string& varName, const std::string& value);
    std::string getTrackedString(const std::string& varName) const;
    std::string resolveIndirectCall(const std::string& varName);
    const std::vector<SensitiveStringEvent>& getDetectedEvents() const;
    void reset();
    void generateReport() const;
};