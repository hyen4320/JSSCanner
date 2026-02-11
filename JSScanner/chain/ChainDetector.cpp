#include "pch.h"
#include "ChainDetector.h"
#include "../model/JsValueVariant.h"


// debug_chain 함수 - Logger의 debug 설정에 따름
static void debug_chain(const std::string& message) {
    core::Log_Debug("JS Scanner - [CHAIN] %s" , message);
}

// Initialize static sets
const std::set<std::string> ChainDetector::DANGEROUS_FUNCTIONS = {
    "eval", "Function", "setTimeout", "setInterval"
};

const std::set<std::string> ChainDetector::DECODER_FUNCTIONS = {
    "atob", "btoa", "unescape", "decodeURIComponent"
};

const std::set<std::string> ChainDetector::OBFUSCATION_FUNCTIONS = {
    "String.fromCharCode", "String.fromCodePoint", "charCodeAt"
};

ChainDetector::ChainDetector(TaintTracker* taintTracker)
    : taintTracker(taintTracker) {
}

void ChainDetector::detectFunctionCall(const std::string& functionName, const std::vector<JsValue>& args, JsValue result,
                                       const std::map<std::string, JsValue>& context) {
    bool isChainRelevant = DECODER_FUNCTIONS.count(functionName) ||
                           DANGEROUS_FUNCTIONS.count(functionName) ||
                           functionName.find("fromCharCode") != std::string::npos ||
                           functionName.find("charCodeAt") != std::string::npos;
        
    if (isChainRelevant) {
        debug_chain("Detecting: " + functionName);
    }
        
    if (DECODER_FUNCTIONS.count(functionName)) {
        handleDecoderFunction(functionName, args, result, context);
    } else if (DANGEROUS_FUNCTIONS.count(functionName)) {
        handleDangerousFunction(functionName, args, result, context);
    } else if (functionName.find("fromCharCode") != std::string::npos || functionName.find("charCodeAt") != std::string::npos) {
        handleObfuscationFunction(functionName, args, result, context);
    }
}

void ChainDetector::handleDecoderFunction(const std::string& functionName, const std::vector<JsValue>& args, JsValue result,
                                          const std::map<std::string, JsValue>& context) {
    if (std::holds_alternative<std::monostate>(result.get()) || args.empty()) return; // result is null/undefined or no args

    JsValue input_val = args[0];
    std::string inputStr;
    if (std::holds_alternative<std::string>(input_val.get())) {
        inputStr = std::get<std::string>(input_val.get());
    } else {
        // Handle other types if necessary, or convert to string representation
        inputStr = "[NonStringInput]"; // Placeholder
    }

    TaintedValue* inputTaint = taintTracker->findTaintByValue(input_val);
    std::string existingChainId;
        
    if (inputTaint != nullptr) {
        existingChainId = findChainForTaint(inputTaint->getValueId());
    }
        
    TaintedValue* tainted = taintTracker->createTaintedValue(
        result, functionName, 6, "Decoded data"
    );
    if (!tainted) return; // Handle error if tainted value creation fails

    std::string resultStr;
    if (std::holds_alternative<std::string>(result.get())) {
        resultStr = std::get<std::string>(result.get());
    } else {
        resultStr = "[NonStringResult]"; // Placeholder
    }

    bool containsDangerousKeyword = 
        resultStr.find("eval") != std::string::npos || 
        resultStr.find("script") != std::string::npos ||
        resultStr.find("function") != std::string::npos ||
        resultStr.find("ActiveX") != std::string::npos;
        
    if (containsDangerousKeyword) {
        if (tainted) {
            // Assuming TaintedValue has an escalateTaint method or similar
            // For now, we can just create a new tainted value with higher level or modify existing
            tainted->taintLevel += 3; // Simple escalation
            tainted->reason += " (Decoded dangerous keyword: " + resultStr.substr(0, (std::min)((size_t)50, resultStr.length())) + ")";
        }
    }

    std::string input_type = "UNKNOWN";
    if (std::holds_alternative<std::string>(input_val.get())) {
        input_type = "STRING";
    } else if (std::holds_alternative<std::vector<JsValue>>(input_val.get())) {
        input_type = "ARRAY";
    } else if (std::holds_alternative<double>(input_val.get())) {
        input_type = "NUMBER";
    } else if (std::holds_alternative<bool>(input_val.get())) {
        input_type = "BOOLEAN";
    } else if (std::holds_alternative<std::map<std::string, JsValue>>(input_val.get())) {
        input_type = "OBJECT";
    }

    std::string output_type = "UNKNOWN";
    if (std::holds_alternative<std::string>(result.get())) {
        output_type = "STRING";
    } else if (std::holds_alternative<std::vector<JsValue>>(result.get())) {
        output_type = "ARRAY";
    } else if (std::holds_alternative<double>(result.get())) {
        output_type = "NUMBER";
    } else if (std::holds_alternative<bool>(result.get())) {
        output_type = "BOOLEAN";
    } else if (std::holds_alternative<std::map<std::string, JsValue>>(result.get())) {
        output_type = "OBJECT";
    }
        
    if (!existingChainId.empty()) {
        AttackChain* chain = activeChains.at(existingChainId).get();
        if (chain != nullptr) {
            DataNode stepInput(
                inputTaint ? inputTaint->getValueId() : "data_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()),
                input_val,
                input_type,
                inputTaint ? inputTaint->getValueId() : "",
                {}
            );
                
            DataNode stepOutput(
                tainted ? tainted->getValueId() : "data_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()),
                result,
                output_type,
                stepInput.dataId,
                {}
            );
                
            ChainStep step(
                "step_" + existingChainId + "_" + std::to_string(chain->getSteps().size() + 1),
                functionName,
                stepInput,
                stepOutput,
                tainted ? tainted->getTaintLevel() : 1,
                context
            );
                
            chain->addStep(step);
            dataToChain[stepOutput.dataId] = existingChainId;
                
            debug_chain("Extended chain: " + existingChainId + 
                                 " with " + functionName + " (multi-layer encoding!)");
            return;
        }
    }
        
    std::string chainId = "chain_" + std::to_string(nextChainId++);
    auto chain = std::make_unique<AttackChain>(chainId);
        
    DataNode inputNode(
        "data_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()),
        input_val,
        "STRING",
        "",
        {}
    );
        
    DataNode outputNode(
        tainted ? tainted->getValueId() : "data_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()),
        result,
        "STRING",
        inputNode.dataId,
        {}
    );
        
    ChainStep step(
        "step_" + chainId + "_1",
        functionName,
        inputNode,
        outputNode,
        tainted ? tainted->getTaintLevel() : 1,
        context
    );
        
    chain->addStep(step);
    dataToChain[outputNode.dataId] = chainId;
    activeChains[chainId] = std::move(chain);
        
    debug_chain("Started chain: " + chainId + " with " + functionName);
}
    
void ChainDetector::handleDangerousFunction(const std::string& functionName, const std::vector<JsValue>& args, JsValue result,
                                            const std::map<std::string, JsValue>& context) {
    if (args.empty()) return;
        
    JsValue input_val = args[0];
    std::string inputStr;
    if (std::holds_alternative<std::string>(input_val.get())) {
        inputStr = std::get<std::string>(input_val.get());
    } else {
        inputStr = "[NonStringInput]"; // Placeholder
    }
        
    TaintedValue* inputTaint = taintTracker->findTaintByValue(input_val);
        
    if (inputTaint != nullptr) {
        std::string chainId = findChainForTaint(inputTaint->getValueId());
            
        if (!chainId.empty()) {
            AttackChain* chain = activeChains.at(chainId).get();
                
            if (chain != nullptr) {
                DataNode stepInput(
                    inputTaint->getValueId(),
                    input_val,
                    "STRING",
                    inputTaint->getValueId(),
                    {}
                );
                    
                TaintedValue* resultTaint = nullptr;
                if (!std::holds_alternative<std::monostate>(result.get())) {
                    resultTaint = taintTracker->createTaintedValue(
                        result, functionName + "_output", 10, "Output of dangerous function"
                    );
                }

                DataNode stepOutput(
                    resultTaint ? resultTaint->getValueId() : "data_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()),
                    result,
                    "ANY",
                    stepInput.dataId,
                    {}
                );
                    
                ChainStep step(
                    "step_" + chainId + "_" + std::to_string(chain->getSteps().size() + 1),
                    functionName,
                    stepInput,
                    stepOutput,
                    10,  // eval etc. are highest severity
                    context
                );
                    
                chain->addStep(step);
                    
                chain->complete("Dangerous function '" + functionName + "' executed with tainted input");
                completedChains.push_back(std::move(*activeChains.at(chainId))); // Move from active to completed
                activeChains.erase(chainId);
                    
                debug_chain("Completed chain: " + chainId + 
                                     " - CRITICAL: " + functionName + " with tainted data!");
                    
                if (chain->verifyCausality()) {
                    debug_chain("Causality VERIFIED for chain: " + chainId);
                } else {
                    debug_chain("Causality verification FAILED for chain: " + chainId);
                }
            }
        } else {
            debug_chain("Tainted input to " + functionName + 
                                 " but no active chain found!");
        }
    } else {
        debug_chain(functionName + " called without tainted input");
    }
}
    
void ChainDetector::handleObfuscationFunction(const std::string& functionName, const std::vector<JsValue>& args, JsValue result,
                                              const std::map<std::string, JsValue>& context) {
    if (std::holds_alternative<std::monostate>(result.get())) return; // result is null/undefined

    TaintedValue* tainted = taintTracker->createTaintedValue(
        result, functionName, 5, "Obfuscated data"
    );
    if (!tainted) return; // Handle error if tainted value creation fails
            
    std::string input_type = "UNKNOWN";
    JsValue input_val_for_step = args.empty() ? JsValue(std::monostate()) : args[0];
    if (std::holds_alternative<std::string>(input_val_for_step.get())) {
        input_type = "STRING";
    } else if (std::holds_alternative<std::vector<JsValue>>(input_val_for_step.get())) {
        input_type = "ARRAY";
    } else if (std::holds_alternative<double>(input_val_for_step.get())) {
        input_type = "NUMBER";
    } else if (std::holds_alternative<bool>(input_val_for_step.get())) {
        input_type = "BOOLEAN";
    } else if (std::holds_alternative<std::map<std::string, JsValue>>(input_val_for_step.get())) {
        input_type = "OBJECT";
    }

    std::string output_type = "UNKNOWN";
    if (std::holds_alternative<std::string>(result.get())) {
        output_type = "STRING";
    } else if (std::holds_alternative<std::vector<JsValue>>(result.get())) {
        output_type = "ARRAY";
    } else if (std::holds_alternative<double>(result.get())) {
        output_type = "NUMBER";
    } else if (std::holds_alternative<bool>(result.get())) {
        output_type = "BOOLEAN";
    } else if (std::holds_alternative<std::map<std::string, JsValue>>(result.get())) {
        output_type = "OBJECT";
    }

    for (auto const& [chainId, chain_ptr] : activeChains) {
        AttackChain* chain = chain_ptr.get();
        if (chain->getSteps().empty()) continue;

        ChainStep lastStep = chain->getSteps().back();
        long long timeDiff = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch() - 
            std::chrono::milliseconds(lastStep.getTimestamp())
        ).count();
                    
        if (timeDiff < 1000) {  // within 1 second
            DataNode stepInput(
                "data_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()),
                input_val_for_step,
                input_type, // Dynamically determined type
                "",
                {}
            );
                        
            DataNode stepOutput(
                tainted ? tainted->getValueId() : "data_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()),
                result,
                output_type,
                stepInput.dataId,
                {}
            );
                        
            ChainStep step(
                "step_" + chain->getChainId() + "_" + std::to_string(chain->getSteps().size() + 1),
                functionName,
                stepInput,
                stepOutput,
                tainted ? tainted->getTaintLevel() : 1,
                context
            );
                        
            chain->addStep(step);
            dataToChain[stepOutput.dataId] = chain->getChainId();
                        
            debug_chain("Added obfuscation step to chain: " + 
                                 chain->getChainId());
            break;
        }
    }
}
    
std::string ChainDetector::findChainForTaint(const std::string& taintValueId) const {
    auto it = dataToChain.find(taintValueId);
    if (it != dataToChain.end()) {
        return it->second;
    }
    return "";
}
    
std::map<std::string, JsValue> ChainDetector::generateReport() const {
    std::map<std::string, JsValue> report;
        
    report["TotalChains"] = static_cast<double>(activeChains.size() + completedChains.size());
    report["ActiveChains"] = static_cast<double>(activeChains.size());
    report["CompletedChains"] = static_cast<double>(completedChains.size());
        
    std::map<std::string, double> typeDistribution;
    for (const auto& chain : completedChains) {
        typeDistribution[chain.getChainType()]++;
    }
    report["ChainTypeDistribution"] = typeDistribution;
        
    AttackChain* mostDangerous = nullptr;
    int maxSeverity = -1;
    for (const auto& chain : completedChains) {
        if (chain.getFinalSeverity() > maxSeverity) {
            maxSeverity = chain.getFinalSeverity();
            mostDangerous = const_cast<AttackChain*>(&chain);
        }
    }
        
    if (mostDangerous != nullptr) {
        report["MostDangerousChain"] = mostDangerous->toJson();
    }
        
    return report;
}
    
void ChainDetector::clear() {
    activeChains.clear();
    completedChains.clear();
    dataToChain.clear();
    nextChainId = 1;
}
    
std::vector<AttackChain*> ChainDetector::getActiveChains() const {
    std::vector<AttackChain*> active;
    for (const auto& pair : activeChains) {
        active.push_back(pair.second.get());
    }
    return active;
}
    
void ChainDetector::printStatus() const {
    std::cout << "\n[CHAIN DETECTOR STATUS]" << std::endl;
    std::cout << "  Active Chains: " << activeChains.size() << std::endl;
    std::cout << "  Completed Chains: " << completedChains.size() << std::endl;
        
    if (!activeChains.empty()) {
        std::cout << "\n  Active:" << std::endl;
        for (const auto& entry : activeChains) {
            AttackChain* chain = entry.second.get();
            std::cout << "    - " << entry.first << ": " << 
                chain->getSteps().size() << " steps, type=" << chain->getChainType() << std::endl;
        }
    }
        
    if (!completedChains.empty()) {
        std::cout << "\n  Completed:" << std::endl;
        for (const auto& chain : completedChains) {
            std::cout << "    - " << chain.getChainId() << ": " << 
                chain.getChainType() << ", severity=" << chain.getFinalSeverity() <<
                ", verified=" << (chain.verifyCausality() ? "true" : "false") << std::endl;
        }
    }
}
// ChainDetector.cpp에 추가
bool ChainDetector::isMultiLayerDecoding(const std::vector<ChainStep>& steps) {
    bool hasAtob = false;
    bool hasTextDecoder = false;
    bool hasUint8Array = false;
    bool hasDocumentWrite = false;
    
    for (const auto& step : steps) {
        if (step.functionName == "atob") hasAtob = true;
        if (step.functionName == "TextDecoder") hasTextDecoder = true;
        if (step.functionName == "Uint8Array.from") hasUint8Array = true;
        if (step.functionName == "document.write") hasDocumentWrite = true;
    }
    
    return hasAtob && hasTextDecoder && hasUint8Array && hasDocumentWrite;
}