#include "pch.h"
#include "SummaryGenerator.h"
#include "../../hooks/HookType.h"
#include <algorithm>
#include <numeric>

std::string SummaryGenerator::convertJsValueToString(const JsValue& val) const {
    return JsValueToString(val);
}

std::string SummaryGenerator::determineThreatLevel(int severity) const {
    if (severity >= 9) return "CRITICAL";
    if (severity >= 7) return "HIGH";
    if (severity >= 5) return "MEDIUM";
    return "LOW";
}

std::string SummaryGenerator::generateDomManipulationSummary(const std::vector<HookEvent>& domEvents) {
    std::vector<HookEvent> documentWriteEvents;
    std::vector<HookEvent> otherDomEvents;
    
    for (const auto& event : domEvents) {
        if (event.name == "document.write") {
            documentWriteEvents.push_back(event);
        } else {
            otherDomEvents.push_back(event);
        }
    }
    
    std::ostringstream summary;
    summary << "Detected " << domEvents.size() << " DOM manipulation operation(s)";
    
    if (!documentWriteEvents.empty()) {
        summary << " including " << documentWriteEvents.size() << " document.write() call(s)";
        
        int scriptTags = 0, iframeTags = 0, externalUrls = 0;
        std::vector<std::string> detectedUrls;
        
        for (const auto& event : documentWriteEvents) {
            std::string content;
            if (!event.args.empty()) {
                content = convertJsValueToString(event.args[0]);
            }
            
            if (content.find("<script") != std::string::npos) scriptTags++;
            if (content.find("<iframe") != std::string::npos) iframeTags++;
            
            size_t urlPos = 0;
            while ((urlPos = content.find("http", urlPos)) != std::string::npos) {
                size_t urlEnd = content.find_first_of(" \"\'>", urlPos);
                if (urlEnd == std::string::npos) urlEnd = content.length();
                std::string url = content.substr(urlPos, urlEnd - urlPos);
                if (detectedUrls.size() < 3) {
                    detectedUrls.push_back(url);
                }
                externalUrls++;
                urlPos = urlEnd;
            }
        }
        
        if (scriptTags > 0) summary << " with " << scriptTags << " <script> tag(s)";
        if (iframeTags > 0) summary << ", " << iframeTags << " <iframe> tag(s)";
        
        if (externalUrls > 0 && !detectedUrls.empty()) {
            summary << ", " << externalUrls << " external URL(s) [URLs: ";
            for (size_t i = 0; i < detectedUrls.size(); ++i) {
                if (i > 0) summary << ", ";
                summary << detectedUrls[i];
            }
            if (externalUrls > detectedUrls.size()) {
                summary << ", and " << (externalUrls - detectedUrls.size()) << " more";
            }
            summary << "]";
        }
    }
    
    if (!otherDomEvents.empty()) {
        summary << " and " << otherDomEvents.size() << " other DOM operation(s)";
    }
    
    summary << ". HIGH XSS RISK - Severity 8/10";
    
    return summary.str();
}

std::string SummaryGenerator::generateLocationChangeSummary(const std::vector<HookEvent>& locationEvents) {
    std::ostringstream summary;
    summary << "Detected " << locationEvents.size() << " page redirection(s) - potential phishing";
    return summary.str();
}

std::string SummaryGenerator::generateAddrManipulationSummary(const std::vector<HookEvent>& addrEvents) {
    std::ostringstream summary;
    summary << "Detected " << addrEvents.size() << " address bar manipulation(s) - URL spoofing risk";
    return summary.str();
}

std::string SummaryGenerator::generateEnvironmentSummary(const std::vector<HookEvent>& envEvents) {
    std::set<std::string> detectedProperties;
    for (const auto& event : envEvents) {
        detectedProperties.insert(event.name);
    }
    
    std::ostringstream summary;
    summary << "Detected environment fingerprinting: " << detectedProperties.size() << " property access(es)";
    return summary.str();
}

std::string SummaryGenerator::generateCryptoSummary(
    int totalChains,
    int totalObfuscations,
    int maxChainLength,
    bool hasEval,
    const std::set<std::string>& techniques) {
    
    std::string threatLevel = hasEval && maxChainLength >= 20 ? "CRITICAL" :
                             hasEval && maxChainLength >= 10 ? "HIGH" :
                             hasEval ? "MEDIUM" :
                             maxChainLength >= 10 ? "MEDIUM" : "LOW";
    
    std::ostringstream summary;
    summary << threatLevel << " - ";
    summary << "Detected " << totalChains << " obfuscation chain"
            << (totalChains > 1 ? "s" : "");
    summary << " using " << totalObfuscations << " encoding/decoding operation"
            << (totalObfuscations > 1 ? "s" : "");
    summary << " across " << techniques.size() << " different technique"
            << (techniques.size() > 1 ? "s" : "");
    
    if (!techniques.empty()) {
        summary << " [Techniques: ";
        int techCount = 0;
        for (const auto& tech : techniques) {
            if (techCount > 0) summary << ", ";
            summary << tech;
            if (++techCount >= 5) break;
        }
        if (techniques.size() > 5) {
            summary << ", +" << (techniques.size() - 5) << " more";
        }
        summary << "]";
    }
    
    if (hasEval) {
        summary << ". Leads to DYNAMIC CODE EXECUTION via eval()";
    }
    
    if (maxChainLength >= 10) {
        summary << ". Longest chain: " << maxChainLength << " layers";
    }
    
    return summary.str();
}

std::string SummaryGenerator::generateAttackChainSummary(const std::vector<AttackChain>& chains) {
    if (chains.empty()) {
        return "No attack chains detected";
    }
    
    int totalSteps = 0;
    int highestSeverity = 0;
    int verifiedChains = 0;
    
    for (const auto& chain : chains) {
        totalSteps += chain.getSteps().size();
        highestSeverity = std::max(highestSeverity, chain.getFinalSeverity());
        if (chain.verifyCausality()) verifiedChains++;
    }
    
    std::string threatLevel = determineThreatLevel(highestSeverity);
    
    std::ostringstream summary;
    summary << "(Total " << totalSteps << " attack steps) ";
    summary << threatLevel << " - ";
    summary << "Detected " << chains.size() << " attack chain" 
            << (chains.size() > 1 ? "s" : "");
    summary << " with " << totalSteps << " step" 
            << (totalSteps > 1 ? "s" : "");
    
    if (verifiedChains > 0) {
        summary << " (" << verifiedChains << " verified)";
    }
    
    return summary.str();
}

std::string SummaryGenerator::generateStaticFindingSummary(
    const std::string& reason,
    int findingCount,
    const std::set<std::string>& variableNames,
    const std::set<std::string>& patterns,
    const std::string& firstSnippet) {
    
    std::ostringstream summary;
    summary << "Detected " << findingCount << " instance(s) of " << reason;
    
    if (!variableNames.empty()) {
        summary << " in " << variableNames.size() << " variable(s)";
        if (variableNames.size() <= 3) {
            summary << " [Variables: ";
            int count = 0;
            for (const auto& varName : variableNames) {
                if (count > 0) summary << ", ";
                summary << varName;
                count++;
            }
            summary << "]";
        }
    }
    
    if (!patterns.empty()) {
        summary << " [Patterns: ";
        int count = 0;
        for (const auto& pattern : patterns) {
            if (count > 0) summary << ", ";
            summary << pattern;
            if (++count >= 5) break;
        }
        if (patterns.size() > 5) {
            summary << ", +" << (patterns.size() - 5) << " more";
        }
        summary << "]";
    }
    
    if (!firstSnippet.empty()) {
        summary << ". Example: \"" << firstSnippet;
        if (firstSnippet.length() >= 200) summary << "...";
        summary << "\"";
    }
    
    return summary.str();
}

std::string SummaryGenerator::generateFetchRequestSummary(const std::vector<HookEvent>& fetchEvents) {
    if (fetchEvents.empty()) {
        return "No fetch requests detected";
    }

    int totalRequests = 0;
    bool hasSensitiveData = false;
    std::set<std::string> methods;
    std::vector<std::string> urls;
    std::vector<std::string> bodies;

    for (const auto& event : fetchEvents) {
        if (event.type != HookType::FETCH_REQUEST) continue;
        totalRequests++;

        if (!event.metadata.empty()) {
            // Method 추출
            auto methodIt = event.metadata.find("method");
            if (methodIt != event.metadata.end()) {
                std::string method = convertJsValueToString(methodIt->second);
                method.erase(std::remove(method.begin(), method.end(), '"'), method.end());
                if (!method.empty() && method != "undefined") {
                    methods.insert(method);
                }
            }

            // URL 추출
            auto urlIt = event.metadata.find("url");
            if (urlIt != event.metadata.end()) {
                std::string url = convertJsValueToString(urlIt->second);
                url.erase(std::remove(url.begin(), url.end(), '"'), url.end());
                if (!url.empty() && urls.size() < 3) {  // 최대 3개만 표시
                    urls.push_back(url);
                }
            }

            // Body 추출
            auto bodyIt = event.metadata.find("body");
            if (bodyIt != event.metadata.end()) {
                std::string body = convertJsValueToString(bodyIt->second);
                body.erase(std::remove(body.begin(), body.end(), '"'), body.end());

                // Body 내용 저장 (최대 3개, 각 100자까지)
                if (!body.empty() && bodies.size() < 3) {
                    std::string bodySnippet = body.length() > 100 ? body.substr(0, 100) + "..." : body;
                    bodies.push_back(bodySnippet);
                }

                // 민감 데이터 체크
                std::string bodyLower = body;
                std::transform(bodyLower.begin(), bodyLower.end(), bodyLower.begin(), ::tolower);

                if (bodyLower.find("password") != std::string::npos ||
                    bodyLower.find("credential") != std::string::npos ||
                    bodyLower.find("token") != std::string::npos ||
                    bodyLower.find("auth") != std::string::npos) {
                    hasSensitiveData = true;
                }
            }
        }
    }

    std::string threatLevel;
    if (hasSensitiveData && (methods.count("POST") > 0 || methods.count("PUT") > 0)) {
        threatLevel = "CRITICAL";
    } else if (methods.count("POST") > 0) {
        threatLevel = "HIGH";
    } else {
        threatLevel = "MEDIUM";
    }

    std::ostringstream summary;
    summary << "Detected " << totalRequests << " fetch request"
            << (totalRequests > 1 ? "s" : "") << " [" << threatLevel << " risk]";

    // Method 정보 추가
    if (!methods.empty()) {
        summary << " - Methods: ";
        int count = 0;
        for (const auto& method : methods) {
            if (count > 0) summary << ", ";
            summary << method;
            count++;
        }
    }

    // URL 정보 추가
    if (!urls.empty()) {
        summary << " - URLs: ";
        for (size_t i = 0; i < urls.size(); ++i) {
            if (i > 0) summary << ", ";
            summary << urls[i];
        }
        if (totalRequests > static_cast<int>(urls.size())) {
            summary << " and " << (totalRequests - urls.size()) << " more";
        }
    }

    // Body 정보 추가
    if (!bodies.empty()) {
        summary << " - Body data: ";
        for (size_t i = 0; i < bodies.size(); ++i) {
            if (i > 0) summary << " | ";
            summary << "[" << (i + 1) << "] " << bodies[i];
        }
        if (totalRequests > static_cast<int>(bodies.size())) {
            summary << " and " << (totalRequests - bodies.size()) << " more";
        }
    }

    if (hasSensitiveData) {
        summary << " [Contains sensitive data]";
    }

    return summary.str();
}
