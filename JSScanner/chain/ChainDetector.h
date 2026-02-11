#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <set>
#include <memory> // For std::unique_ptr
#include <map>    // For std::map in generateReport

#include "../core/TaintTracker.h"
#include "AttackChain.h"
#include "../model/JsValueVariant.h"

class ChainDetector {
private:
    TaintTracker* taintTracker; // Injected dependency

    // Active chains (chainId -> AttackChain)
    std::unordered_map<std::string, std::unique_ptr<AttackChain>> activeChains;

    // Completed chains
    std::vector<AttackChain> completedChains;

    // Data ID -> Chain ID mapping (which data belongs to which chain)
    std::unordered_map<std::string, std::string> dataToChain;

    // Chain ID generator
    int nextChainId = 1;

    // Dangerous function patterns
    static const std::set<std::string> DANGEROUS_FUNCTIONS;
    static const std::set<std::string> DECODER_FUNCTIONS;
    static const std::set<std::string> OBFUSCATION_FUNCTIONS;

    // Helper methods
    void handleDecoderFunction(const std::string& functionName, const std::vector<JsValue>& args, JsValue result,
                               const std::map<std::string, JsValue>& context);
    void handleDangerousFunction(const std::string& functionName, const std::vector<JsValue>& args, JsValue result,
                                const std::map<std::string, JsValue>& context);
    void handleObfuscationFunction(const std::string& functionName, const std::vector<JsValue>& args, JsValue result,
                                  const std::map<std::string, JsValue>& context);
    std::string findChainForTaint(const std::string& taintValueId) const;
    bool isMultiLayerDecoding(const std::vector<ChainStep>& steps);

public:
    ChainDetector(TaintTracker* taintTracker);
    ~ChainDetector() = default;

    // Detect function call - start or extend a chain
    void detectFunctionCall(const std::string& functionName, const std::vector<JsValue>& args, JsValue result,
                            const std::map<std::string, JsValue>& context);

    // Generate chain Detection report
    std::map<std::string, JsValue> generateReport() const;

    // Reset internal state
    void clear();

    // Getters
    const std::vector<AttackChain>& getCompletedChains() const { return completedChains; }
    // Note: Returning raw pointers for active chains for now, consider const references or copies if ownership is complex
    std::vector<AttackChain*> getActiveChains() const;
    TaintTracker* getTaintTracker() const { return taintTracker; }

    // Debug: print current status
    void printStatus() const;
};
