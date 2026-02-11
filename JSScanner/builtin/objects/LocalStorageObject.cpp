#include "pch.h"
#include "LocalStorageObject.h"
#include "../helpers/JSValueConverter.h"
#include "../helpers/SensitiveKeywordDetector.h"
#include "../../model/JsValueVariant.h"
#include "../../core/JSAnalyzer.h"
#include <algorithm>

namespace LocalStorageObject {
    // 🔥 CRITICAL FIX: 멀티스레드 환경에서 데이터 레이스 방지
    // 각 스레드마다 독립적인 localStorage 사용
    thread_local std::unordered_map<std::string, std::string> g_local_storage = {
        {"username", "stored.user@example.com"},
        {"userEmail", "stored.user@example.com"},
        {"organization", "storedcorp"}
    };

    static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
        return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
    }

    static int calculateLocalStorageSeverity(const std::string& key, const std::string& value, std::string& keywordSummary) {
        // 🎯 0점에서 시작 (localStorage 접근 자체는 정상 동작)
        int severity = 0;

        // 1. Key에서 민감한 키워드 감지 (+3점)
        std::string keyMatches;
        if (SensitiveKeywordDetector::detect(key, keyMatches)) {
            severity += 3;
            keywordSummary += keyMatches;
        }

        // 2. Value에서 민감한 키워드 감지 (+3점)
        std::string valueMatches;
        if (!value.empty() && SensitiveKeywordDetector::detect(value, valueMatches)) {
            severity += 3;
            if (!keywordSummary.empty()) {
                keywordSummary += ", ";
            }
            keywordSummary += valueMatches;
        }
        
        // 🔥 NEW: 3. 매우 민감한 키워드 감지 (+4점 추가)
        std::vector<std::string> criticalKeywords = {
            "password", "passwd", "pwd", "secret", "api_key", "apikey",
            "credit_card", "creditcard", "ssn", "social_security",
            "private_key", "privatekey", "auth_token", "authtoken"
        };
        
        std::string lowerKey = key;
        std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
        std::string lowerValue = value;
        std::transform(lowerValue.begin(), lowerValue.end(), lowerValue.begin(), ::tolower);
        
        for (const auto& keyword : criticalKeywords) {
            if (lowerKey.find(keyword) != std::string::npos || 
                lowerValue.find(keyword) != std::string::npos) {
                severity += 4;  // 매우 위험
                break;  // 한 번만 추가
            }
        }

        return std::min(severity, 10);  // 최대 10점으로 제한
    }

    static void trackStorageChain(JSAnalyzerContext* a_ctx, const std::string& name, 
                                   const std::vector<JsValue>& args, const JsValue& result) {
        if (a_ctx && a_ctx->chainTrackerManager) {
            a_ctx->chainTrackerManager->trackFunctionCall(name, args, result);
        }
    }

    JSValue js_localStorage_getItem(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        (void)this_val;
        if (argc < 1) {
            return JS_NULL;
        }

        std::string key = JSValueConverter::toString(ctx, argv[0]);
        std::string value;
        auto it = g_local_storage.find(key);
        if (it != g_local_storage.end()) {
            value = it->second;
        }

        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        std::map<std::string, JsValue> metadata;
        metadata["key"] = JsValue(key);
        metadata["length"] = JsValue(static_cast<double>(value.size()));

        std::string keywordSummary;
        int severity = calculateLocalStorageSeverity(key, value, keywordSummary);
        if (!keywordSummary.empty()) {
            metadata["keywords"] = JsValue(keywordSummary);
        }
        if (!value.empty()) {
            metadata["value"] = JsValue(value);
        }

        JsValue resultValue = value.empty() ? JsValue() : JsValue(value);

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::DATA_EXFILTRATION, "localStorage.getItem", 
                {JsValue(key)}, resultValue, metadata, severity});
        }

        trackStorageChain(a_ctx, "localStorage.getItem", {JsValue(key)}, resultValue);

        if (a_ctx && a_ctx->dynamicStringTracker && !value.empty()) {
            a_ctx->dynamicStringTracker->trackString("localStorage." + key, value);
        }

        if (value.empty()) {
            return JS_NULL;
        }
        return JS_NewString(ctx, value.c_str());
    }

    JSValue js_localStorage_setItem(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        (void)this_val;
        if (argc < 2) {
            return JS_UNDEFINED;
        }

        std::string key = JSValueConverter::toString(ctx, argv[0]);
        std::string value = JSValueConverter::toString(ctx, argv[1]);
        g_local_storage[key] = value;

        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        std::map<std::string, JsValue> metadata;
        metadata["key"] = JsValue(key);
        metadata["length"] = JsValue(static_cast<double>(value.size()));

        std::string keywordSummary;
        int severity = calculateLocalStorageSeverity(key, value, keywordSummary);
        if (!keywordSummary.empty()) {
            metadata["keywords"] = JsValue(keywordSummary);
        }

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::DATA_EXFILTRATION, "localStorage.setItem", 
                {JsValue(key), JsValue(value)}, JsValue(std::monostate()), metadata, severity});
        }

        trackStorageChain(a_ctx, "localStorage.setItem", {JsValue(key), JsValue(value)}, JsValue(std::monostate()));

        if (a_ctx && a_ctx->dynamicStringTracker && !value.empty()) {
            a_ctx->dynamicStringTracker->trackString("localStorage." + key, value);
        }

        return JS_UNDEFINED;
    }

    JSValue js_localStorage_removeItem(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        (void)this_val;
        if (argc < 1) {
            return JS_UNDEFINED;
        }

        std::string key = JSValueConverter::toString(ctx, argv[0]);
        std::string removedValue;
        auto it = g_local_storage.find(key);
        if (it != g_local_storage.end()) {
            removedValue = it->second;
            g_local_storage.erase(it);
        }

        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        std::map<std::string, JsValue> metadata;
        metadata["key"] = JsValue(key);
        metadata["hadValue"] = JsValue(static_cast<double>(removedValue.empty() ? 0 : 1));

        std::string keywordSummary;
        int severity = calculateLocalStorageSeverity(key, removedValue, keywordSummary);
        severity = (std::max)(severity, removedValue.empty() ? 5 : 7);
        if (!keywordSummary.empty()) {
            metadata["keywords"] = JsValue(keywordSummary);
        }

        if (!removedValue.empty()) {
            metadata["value"] = JsValue(removedValue);
        }

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({HookType::DATA_EXFILTRATION, "localStorage.removeItem", 
                {JsValue(key)}, JsValue(std::monostate()), metadata, severity});
        }

        trackStorageChain(a_ctx, "localStorage.removeItem", {JsValue(key)}, JsValue(std::monostate()));

        return JS_UNDEFINED;
    }

    JSValue js_localStorage_clear(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        (void)this_val;
        (void)argc;
        (void)argv;

        std::size_t cleared = g_local_storage.size();
        g_local_storage.clear();

        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (a_ctx && a_ctx->dynamicAnalyzer) {
            std::map<std::string, JsValue> metadata;
            metadata["cleared"] = JsValue(static_cast<double>(cleared));
            a_ctx->dynamicAnalyzer->recordEvent({HookType::DATA_EXFILTRATION, "localStorage.clear", 
                {}, JsValue(std::monostate()), metadata, 5});
        }

        trackStorageChain(a_ctx, "localStorage.clear", {}, JsValue(std::monostate()));

        return JS_UNDEFINED;
    }

    void registerLocalStorageObject(JSContext* ctx, JSValue global_obj) {
        JSValue localStorage_obj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, localStorage_obj, "getItem", 
            JS_NewCFunction(ctx, js_localStorage_getItem, "getItem", 1));
        JS_SetPropertyStr(ctx, localStorage_obj, "setItem", 
            JS_NewCFunction(ctx, js_localStorage_setItem, "setItem", 2));
        JS_SetPropertyStr(ctx, localStorage_obj, "removeItem", 
            JS_NewCFunction(ctx, js_localStorage_removeItem, "removeItem", 1));
        JS_SetPropertyStr(ctx, localStorage_obj, "clear", 
            JS_NewCFunction(ctx, js_localStorage_clear, "clear", 0));
        JS_SetPropertyStr(ctx, global_obj, "localStorage", localStorage_obj);
    }
}
