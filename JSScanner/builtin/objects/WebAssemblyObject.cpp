#include "pch.h"
#include "WebAssemblyObject.h"
#include "../helpers/JSValueConverter.h"
#include "../../core/JSAnalyzer.h"
#include <string>
#include <vector>

namespace WebAssemblyObject {

static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
    return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
}

// ============================================================================
// Helper Functions for WASM Analysis
// ============================================================================

struct WasmModuleInfo {
    size_t byte_size = 0;
    bool has_memory = false;
    bool has_table = false;
    bool has_crypto_imports = false;
    bool has_network_imports = false;
    int function_count = 0;
    int import_count = 0;
    std::vector<std::string> suspicious_imports;
};

static bool isCryptoMiningPattern(const WasmModuleInfo& info) {
    // Crypto mining patterns:
    // 1. Large number of functions (>100)
    // 2. Has memory section (for hash computation)
    // 3. Large byte size (>50KB)
    return info.function_count > 100 && 
           info.has_memory && 
           info.byte_size > 50000;
}

static bool isSuspiciousImport(const std::string& import_name) {
    static const std::vector<std::string> suspicious = {
        "fetch", "xhr", "websocket", "crypto", 
        "eval", "function", "worker", "storage"
    };
    
    for (const auto& pattern : suspicious) {
        if (import_name.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

static WasmModuleInfo analyzeWasmBuffer(JSContext* ctx, JSValueConst buffer) {
    WasmModuleInfo info;
    
    // Get buffer size
    size_t size = 0;
    uint8_t* data = JS_GetArrayBuffer(ctx, &size, buffer);
    
    if (data && size > 8) {
        info.byte_size = size;
        
        // Check WASM magic number (0x00 0x61 0x73 0x6d)
        if (data[0] == 0x00 && data[1] == 0x61 && 
            data[2] == 0x73 && data[3] == 0x6d) {
            
            // Parse WASM sections (simplified)
            size_t offset = 8; // Skip magic + version
            
            while (offset < size - 5) {
                uint8_t section_id = data[offset++];
                
                // Read section size (simplified LEB128)
                uint32_t section_size = data[offset++];
                
                switch (section_id) {
                    case 1: // Type section
                        info.function_count++;
                        break;
                    case 2: // Import section
                        info.import_count++;
                        info.has_network_imports = true; // Simplified
                        break;
                    case 3: // Function section
                        info.function_count += section_size / 2; // Rough estimate
                        break;
                    case 4: // Table section
                        info.has_table = true;
                        break;
                    case 5: // Memory section
                        info.has_memory = true;
                        break;
                }
                
                offset += section_size;
                if (offset >= size) break;
            }
        }
    }
    
    return info;
}

// ============================================================================
// Registration
// ============================================================================

void registerWebAssemblyObject(JSContext* ctx, JSValue global_obj) {
    JSValue wasm_obj = JS_NewObject(ctx);
    
    JS_SetPropertyStr(ctx, wasm_obj, "instantiate", 
        JS_NewCFunction(ctx, js_wasm_instantiate, "instantiate", 2));
    JS_SetPropertyStr(ctx, wasm_obj, "compile", 
        JS_NewCFunction(ctx, js_wasm_compile, "compile", 1));

    JS_SetPropertyStr(ctx, global_obj, "WebAssembly", wasm_obj);
}

// ============================================================================
// WASM Methods
// ============================================================================

JSValue js_wasm_instantiate(JSContext* ctx, JSValueConst this_val, 
                            int argc, JSValueConst* argv) {
    if (argc < 1) return JS_UNDEFINED;
    
    WasmModuleInfo info;
    std::string imports_info;
    std::vector<JsValue> args_vec;
    
    // Analyze WASM module
    if (JS_IsObject(argv[0])) {
        info = analyzeWasmBuffer(ctx, argv[0]);
        args_vec.push_back(JsValue("[ArrayBuffer]"));
        
        // Analyze imports (second argument)
        if (argc > 1 && JS_IsObject(argv[1])) {
            JSPropertyEnum* props;
            uint32_t prop_count;
            
            if (JS_GetOwnPropertyNames(ctx, &props, &prop_count, argv[1], 
                JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0) {
                
                for (uint32_t i = 0; i < prop_count; i++) {
                    JSValue prop_name = JS_AtomToString(ctx, props[i].atom);
                    const char* name_str = JS_ToCString(ctx, prop_name);
                    
                    if (name_str) {
                        std::string import_name(name_str);
                        if (isSuspiciousImport(import_name)) {
                            info.suspicious_imports.push_back(import_name);
                            info.has_crypto_imports = true;
                        }
                        imports_info += import_name + ", ";
                        JS_FreeCString(ctx, name_str);
                    }
                    JS_FreeValue(ctx, prop_name);
                }
                
                js_free(ctx, props);
            }
            args_vec.push_back(JsValue(imports_info));
        }
    }

    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        std::map<std::string, JsValue> metadata;
        metadata["module_size"] = JsValue(static_cast<double>(info.byte_size));
        metadata["function_count"] = JsValue(static_cast<double>(info.function_count));
        metadata["import_count"] = JsValue(static_cast<double>(info.import_count));
        metadata["has_memory"] = JsValue(info.has_memory);
        metadata["has_table"] = JsValue(info.has_table);
        
        int severity = 7;
        std::string reason;
        
        // Determine severity based on analysis
        if (isCryptoMiningPattern(info)) {
            severity = 10;
            reason = "CRYPTO MINING DETECTED!";
            metadata["pattern"] = JsValue("crypto_mining");
        } else if (info.has_crypto_imports || !info.suspicious_imports.empty()) {
            severity = 9;
            reason = "Suspicious imports detected";
            
            if (!info.suspicious_imports.empty()) {
                std::string imports_str;
                for (const auto& imp : info.suspicious_imports) {
                    imports_str += imp + ", ";
                }
                metadata["suspicious_imports"] = JsValue(imports_str);
            }
        } else if (info.byte_size > 100000) {
            severity = 8;
            reason = "Large WASM module >100KB";
        }
        
        if (!reason.empty()) {
            metadata["reason"] = JsValue(reason);
        }
        
        if (!imports_info.empty()) {
            metadata["all_imports"] = JsValue(imports_info);
        }
        
        a_ctx->dynamicAnalyzer->recordEvent({
            HookType::WASM_INSTANTIATE,
            "WebAssembly.instantiate",
            args_vec,
            JsValue(),
            metadata,
            severity
        });
    }

    // Return mock promise with module
    JSValue promise = JS_NewObject(ctx);
    JSValue module = JS_NewObject(ctx);
    JSValue instance = JS_NewObject(ctx);
    
    // Mock exports object
    JSValue exports = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, instance, "exports", exports);
    
    JSValue result = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, result, "module", module);
    JS_SetPropertyStr(ctx, result, "instance", instance);
    
    JS_SetPropertyStr(ctx, promise, "then", 
        JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, 
                                int argc, JSValueConst* argv) -> JSValue {
            if (argc > 0 && JS_IsFunction(ctx, argv[0])) {
                // Call the callback with mock result
                JSValue result = JS_GetPropertyStr(ctx, this_val, "_result");
                JSValue callback_result = JS_Call(ctx, argv[0], JS_UNDEFINED, 1, &result);
                JS_FreeValue(ctx, result);
                return callback_result;
            }
            return JS_UNDEFINED;
        }, "then", 1));
    
    JS_SetPropertyStr(ctx, promise, "_result", result);
    
    return promise;
}

JSValue js_wasm_compile(JSContext* ctx, JSValueConst this_val, 
                       int argc, JSValueConst* argv) {
    if (argc < 1) return JS_UNDEFINED;
    
    WasmModuleInfo info;
    std::vector<JsValue> args_vec;
    
    // Analyze WASM module
    if (JS_IsObject(argv[0])) {
        info = analyzeWasmBuffer(ctx, argv[0]);
        args_vec.push_back(JsValue("[ArrayBuffer]"));
    }

    JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
    if (a_ctx && a_ctx->dynamicAnalyzer) {
        std::map<std::string, JsValue> metadata;
        metadata["module_size"] = JsValue(static_cast<double>(info.byte_size));
        metadata["function_count"] = JsValue(static_cast<double>(info.function_count));
        metadata["has_memory"] = JsValue(info.has_memory);
        
        int severity = 7;
        std::string reason;
        
        if (isCryptoMiningPattern(info)) {
            severity = 10;
            reason = "CRYPTO MINING PATTERN!";
        } else if (info.byte_size > 100000) {
            severity = 8;
            reason = "Large module compilation";
        }
        
        if (!reason.empty()) {
            metadata["reason"] = JsValue(reason);
        }
        
        a_ctx->dynamicAnalyzer->recordEvent({
            HookType::WASM_COMPILE,
            "WebAssembly.compile",
            args_vec,
            JsValue(),
            metadata,
            severity
        });
    }

    JSValue promise = JS_NewObject(ctx);
    JSValue module = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, promise, "_module", module);
    
    JS_SetPropertyStr(ctx, promise, "then", 
        JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, 
                                int argc, JSValueConst* argv) -> JSValue {
            if (argc > 0 && JS_IsFunction(ctx, argv[0])) {
                JSValue module = JS_GetPropertyStr(ctx, this_val, "_module");
                JSValue result = JS_Call(ctx, argv[0], JS_UNDEFINED, 1, &module);
                JS_FreeValue(ctx, module);
                return result;
            }
            return JS_UNDEFINED;
        }, "then", 1));
    
    return promise;
}

} // namespace WebAssemblyObject
