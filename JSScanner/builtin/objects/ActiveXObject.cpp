#include "pch.h"
#include "ActiveXObject.h"
#include "../../hooks/Hook.h"
#include "../../core/DynamicStringTracker.h"
#include "../../core/ChainTrackerManager.h"
#include "../../core/JSAnalyzer.h"

const std::set<std::string> ActiveXObject::DANGEROUS_PROGIDS = {
    "WScript.Shell",
    "Shell.Application",
    "Scripting.FileSystemObject",
    "ADODB.Stream",
    "Microsoft.XMLHTTP",
    "Msxml2.XMLHTTP",
    "WinHttp.WinHttpRequest"
};

const std::set<std::string> ActiveXObject::FILE_SYSTEM_PROGIDS = {
    "Scripting.FileSystemObject",
    "ADODB.Stream",
    "Scripting.Dictionary"
};

const std::set<std::string> ActiveXObject::SHELL_PROGIDS = {
    "WScript.Shell",
    "Shell.Application"
};

const std::set<std::string> ActiveXObject::NETWORK_PROGIDS = {
    "Microsoft.XMLHTTP",
    "Msxml2.XMLHTTP",
    "Msxml2.XMLHTTP.3.0",
    "Msxml2.XMLHTTP.6.0",
    "WinHttp.WinHttpRequest",
    "WinHttp.WinHttpRequest.5.1"
};

// 🔥 런타임에서 Class ID 가져오기 위한 구조체 (JSAnalyzer.cpp에 정의됨)
struct RuntimeClassIDs {
    JSClassID xhr_class_id;
    JSClassID activex_class_id;
};

// 🔥 Context에서 ActiveX Class ID 가져오기
static JSClassID getActiveXClassID(JSContext* ctx) {
    JSRuntime* rt = JS_GetRuntime(ctx);
    RuntimeClassIDs* classIDs = static_cast<RuntimeClassIDs*>(JS_GetRuntimeOpaque(rt));
    return classIDs ? classIDs->activex_class_id : 0;
}

ActiveXObject* ActiveXObject::getThis(JSValueConst this_val) {
    // 🔥 deprecated - context 없이는 Class ID를 알 수 없음
    return nullptr;
}

// 🔥 Context를 사용하여 안전하게 가져오기
ActiveXObject* ActiveXObject::getThis(JSContext* ctx, JSValueConst this_val) {
    JSClassID classID = getActiveXClassID(ctx);
    if (classID == 0) return nullptr;
    return static_cast<ActiveXObject*>(JS_GetOpaque(this_val, classID));
}

ActiveXObject::ActiveXObject(JSContext* ctx, JSAnalyzerContext* a_ctx, const std::string& progID)
    : ctx(ctx), a_ctx(a_ctx), progID(progID) {
    rt = JS_GetRuntime(ctx);
    analyzeActiveXSecurity(progID);
}

ActiveXObject::~ActiveXObject() {
    // ⚠️ CRITICAL: 소멸자에서 JSValue 해제는 위험함
    // Runtime 소멸 중에는 ctx가 이미 유효하지 않을 수 있음
    // finalizer가 호출되면 ctx가 nullptr로 설정되므로, QuickJS GC가 자동으로 정리함
    // 따라서 명시적 해제를 하지 않고 참조만 제거
    if (ctx) {
        // ctx가 있어도 Runtime 소멸 중이라면 JS_FreeValue는 크래시 유발
        // QuickJS GC에 맡기는 것이 가장 안전
        for (auto& pair : properties) {
            pair.second = JS_UNDEFINED;  // 참조만 제거
        }
    }
    properties.clear();
}

void ActiveXObject::analyzeActiveXSecurity(const std::string& progID) {
    if (!a_ctx) return;

    int severity = 3;  // default medium
    std::string category = "activex_usage";

    if (DANGEROUS_PROGIDS.find(progID) != DANGEROUS_PROGIDS.end()) {
        severity = 5;  // critical
        category = "dangerous_activex";
    } else if (FILE_SYSTEM_PROGIDS.find(progID) != FILE_SYSTEM_PROGIDS.end()) {
        severity = 4;  // high
        category = "filesystem_access";
    } else if (SHELL_PROGIDS.find(progID) != SHELL_PROGIDS.end()) {
        severity = 5;  // critical
        category = "shell_execution";
    } else if (NETWORK_PROGIDS.find(progID) != NETWORK_PROGIDS.end()) {
        severity = 3;  // medium
        category = "network_request";
    }

    std::string message = "ActiveXObject created: " + progID;

    if (a_ctx->chainTrackerManager) {
        a_ctx->chainTrackerManager->trackFunctionCall(
            "ActiveXObject",
            {JsValue(progID)},
            JsValue(std::monostate())
        );
    }

    if (a_ctx->dynamicAnalyzer) {
        std::map<std::string, JsValue> metadata;
        metadata["progID"] = JsValue(progID);
        metadata["category"] = JsValue(category);
        metadata["message"] = JsValue(message);

        HookEvent event(
            HookType::ACTIVEX_OBJECT_CREATION,
            "ActiveXObject",
            {JsValue(progID)},
            JsValue(std::monostate()),
            metadata,
            severity
        );
        a_ctx->dynamicAnalyzer->recordEvent(event);
    }
}

void ActiveXObject::analyzeMethodCall(const std::string& methodName, const std::vector<std::string>& args) {
    if (!a_ctx) return;

    int severity = 3;  // default medium
    std::string category = "activex_method";
    std::vector<std::string> detectionTags;
    int riskScore = 0;  // 위험도 점수

    // Analyze dangerous method calls
    if (SHELL_PROGIDS.find(progID) != SHELL_PROGIDS.end()) {
        if (methodName == "Run" || methodName == "Exec" || methodName == "ShellExecute") {
            severity = 5;  // base critical
            category = "command_execution";
            riskScore += 3;  // 기본 위험도
            
            // 추가 위험 패턴 분석
            for (const auto& arg : args) {
                std::string lowerArg = arg;
                std::transform(lowerArg.begin(), lowerArg.end(), lowerArg.begin(), ::tolower);
                
                // PowerShell 명령어 감지
                if (lowerArg.find("powershell") != std::string::npos) {
                    detectionTags.push_back("powershell_execution");
                    riskScore += 2;
                    
                    // 난독화 기법 감지
                    if (lowerArg.find("-noprofile") != std::string::npos || 
                        lowerArg.find("-windowstyle hidden") != std::string::npos ||
                        lowerArg.find("-encodedcommand") != std::string::npos) {
                        detectionTags.push_back("powershell_obfuscation");
                        riskScore += 3;
                    }
                }
                
                // Base64 인코딩 감지
                if (lowerArg.find("frombase64string") != std::string::npos ||
                    lowerArg.find("convert::frombase64") != std::string::npos) {
                    detectionTags.push_back("base64_encoded_payload");
                    riskScore += 3;
                }
                
                // 원격 다운로드 감지
                if (lowerArg.find("downloadstring") != std::string::npos ||
                    lowerArg.find("downloadfile") != std::string::npos ||
                    lowerArg.find("webclient") != std::string::npos ||
                    lowerArg.find("invoke-webrequest") != std::string::npos) {
                    detectionTags.push_back("remote_download");
                    riskScore += 4;
                }
                
                // Invoke-Expression (악성 코드 실행) 감지
                if (lowerArg.find("invoke-expression") != std::string::npos ||
                    lowerArg.find("iex") != std::string::npos) {
                    detectionTags.push_back("invoke_expression");
                    riskScore += 4;
                }
                
                // 리플렉션 기반 실행 감지
                if (lowerArg.find("reflection.assembly") != std::string::npos ||
                    lowerArg.find("::load(") != std::string::npos ||
                    lowerArg.find(".invoke(") != std::string::npos) {
                    detectionTags.push_back("reflection_execution");
                    riskScore += 5;
                }
                
                // 의심스러운 URL 패턴 감지
                if (lowerArg.find("http://") != std::string::npos ||
                    lowerArg.find("https://") != std::string::npos) {
                    detectionTags.push_back("external_url");
                    riskScore += 1;
                    
                    // 특정 의심스러운 도메인/서비스
                    if (lowerArg.find("pastefy.app") != std::string::npos ||
                        lowerArg.find("pastebin.com") != std::string::npos ||
                        lowerArg.find("raw.githubusercontent") != std::string::npos) {
                        detectionTags.push_back("paste_service");
                        riskScore += 2;
                    }
                }
            }
            
            // 위험도에 따라 severity 재계산
            if (riskScore >= 15) {
                severity = 10;  // EXTREME - 극도로 위험
            } else if (riskScore >= 10) {
                severity = 9;   // CRITICAL - 매우 위험
            } else if (riskScore >= 7) {
                severity = 8;   // CRITICAL - 위험
            } else if (riskScore >= 5) {
                severity = 7;   // HIGH - 상당한 위험
            }
        }
    }

    if (FILE_SYSTEM_PROGIDS.find(progID) != FILE_SYSTEM_PROGIDS.end()) {
        if (methodName == "DeleteFile" || methodName == "DeleteFolder" ||
            methodName == "CopyFile" || methodName == "MoveFile" ||
            methodName == "CreateTextFile" || methodName == "OpenTextFile") {
            severity = 4;  // high
            category = "file_operation";
        }
    }

    std::string message = "ActiveXObject method call: " + progID + "." + methodName;
    if (!args.empty()) {
        message += " with args: [";
        for (size_t i = 0; i < args.size(); ++i) {
            if (i > 0) message += ", ";
            message += args[i];
        }
        message += "]";
    }

    if (a_ctx->chainTrackerManager) {
        std::vector<JsValue> jsArgs;
        for (const auto& arg : args) {
            jsArgs.push_back(JsValue(arg));
        }
        a_ctx->chainTrackerManager->trackFunctionCall(
            progID + "." + methodName,
            jsArgs,
            JsValue(std::monostate())
        );
    }

    if (a_ctx->dynamicAnalyzer) {
        std::map<std::string, JsValue> metadata;
        metadata["progID"] = JsValue(progID);
        metadata["method"] = JsValue(methodName);
        metadata["category"] = JsValue(category);
        metadata["message"] = JsValue(message);
        
        // 탐지 태그 추가
        if (!detectionTags.empty()) {
            std::string tagsStr = "";
            for (size_t i = 0; i < detectionTags.size(); ++i) {
                if (i > 0) tagsStr += ", ";
                tagsStr += detectionTags[i];
            }
            metadata["detection_tags"] = JsValue(tagsStr);
        }
        
        std::vector<JsValue> jsArgs;
        for (const auto& arg : args) {
            jsArgs.push_back(JsValue(arg));
        }

        HookEvent event(
            HookType::ACTIVEX_METHOD_CALL,
            progID + "." + methodName,
            jsArgs,
            JsValue(std::monostate()),
            metadata,
            severity
        );
        a_ctx->dynamicAnalyzer->recordEvent(event);
        
        // 위험한 패턴이 감지되면 별도 Detection 생성
        if (!detectionTags.empty() && a_ctx->findings) {
            htmljs_scanner::Detection detection;
            detection.name= "JSScanner.MALICIOUS_ACTIVEX_EXECUTION";
            detection.severity = severity;  // 계산된 severity 사용
            detection.line = 0;
            
            std::string reason = "Malicious ActiveXObject execution detected: " + progID + "." + methodName;
            reason += " [Risk Score: " + std::to_string(riskScore) + "]";
            if (!detectionTags.empty()) {
                reason += " [Tags: ";
                for (size_t i = 0; i < detectionTags.size(); ++i) {
                    if (i > 0) reason += ", ";
                    reason += detectionTags[i];
                }
                reason += "]";
            }
            detection.reason = reason;
            
            // 첫 번째 인자만 샘플로 추가 (너무 길면 잘라냄)
            if (!args.empty()) {
                std::string sample = args[0];
                if (sample.length() > 500) {
                    sample = sample.substr(0, 500) + "... [truncated]";
                }
                detection.features["command"] = sample;
            }
            
            detection.features["progID"] = progID;
            detection.features["method"] = methodName;
            detection.features["risk_score"] = std::to_string(riskScore);
            
            // Severity 레벨 텍스트 변환
            std::string severityLevel;
            if (severity >= 9) {
                severityLevel = "EXTREME";
            } else if (severity >= 7) {
                severityLevel = "CRITICAL";
            } else if (severity >= 5) {
                severityLevel = "HIGH";
            } else {
                severityLevel = "MEDIUM";
            }
            detection.features["severity_level"] = severityLevel;
            
            a_ctx->findings->push_back(detection);
        }
    }
}

bool ActiveXObject::isSensitiveProgID(const std::string& progID) const {
    return DANGEROUS_PROGIDS.find(progID) != DANGEROUS_PROGIDS.end() ||
           FILE_SYSTEM_PROGIDS.find(progID) != FILE_SYSTEM_PROGIDS.end() ||
           SHELL_PROGIDS.find(progID) != SHELL_PROGIDS.end();
}

std::string ActiveXObject::generateMockResponse(const std::string& methodName) {
    // Generate mock responses for common methods
    if (methodName == "Run" || methodName == "Exec") {
        return "0"; // Success code
    }
    if (methodName == "CreateTextFile" || methodName == "OpenTextFile") {
        return "[MockFileObject]";
    }
    if (methodName == "GetFolder" || methodName == "GetFile") {
        return "[MockFileSystemObject]";
    }
    if (methodName == "Send" || methodName == "Open") {
        return ""; // Empty response for network operations
    }
    return "[MockResult]";
}

JSValue ActiveXObject::js_constructor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv) {
    JSAnalyzerContext* a_ctx = static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));

    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "ActiveXObject requires a ProgID argument");
    }

    const char* progID_str = JS_ToCString(ctx, argv[0]);
    if (!progID_str) {
        return JS_EXCEPTION;
    }

    std::string progID(progID_str);
    JS_FreeCString(ctx, progID_str);

    // Create the ActiveXObject instance
    ActiveXObject* axObj = new ActiveXObject(ctx, a_ctx, progID);

    // 🔥 런타임에서 Class ID 가져오기
    JSClassID classID = getActiveXClassID(ctx);
    if (classID == 0) {
        delete axObj;
        return JS_ThrowInternalError(ctx, "ActiveXObject class not registered");
    }
    
    JSValue obj = JS_NewObjectClass(ctx, classID);
    if (JS_IsException(obj)) {
        delete axObj;
        return obj;
    }

    JS_SetOpaque(obj, axObj);

    // Add common methods based on ProgID type
    if (axObj->isSensitiveProgID(progID)) {
        // Add mock methods
        JS_SetPropertyStr(ctx, obj, "Run",
            JS_NewCFunction(ctx, js_run, "Run", 1));
        JS_SetPropertyStr(ctx, obj, "Exec",
            JS_NewCFunction(ctx, js_exec, "Exec", 1));
        JS_SetPropertyStr(ctx, obj, "CreateTextFile",
            JS_NewCFunction(ctx, js_createTextFile, "CreateTextFile", 1));
        JS_SetPropertyStr(ctx, obj, "OpenTextFile",
            JS_NewCFunction(ctx, js_openTextFile, "OpenTextFile", 1));
        JS_SetPropertyStr(ctx, obj, "DeleteFile",
            JS_NewCFunction(ctx, js_deleteFile, "DeleteFile", 1));
        JS_SetPropertyStr(ctx, obj, "Send",
            JS_NewCFunction(ctx, js_send, "Send", 1));
        JS_SetPropertyStr(ctx, obj, "Open",
            JS_NewCFunction(ctx, js_open, "Open", 2));
    }

    return obj;
}

JSValue ActiveXObject::js_method_call(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    ActiveXObject* axObj = getThis(ctx, this_val);
    if (!axObj) {
        return JS_EXCEPTION;
    }

    // Method name은 함수를 등록할 때 이름으로 사용되므로, 
    // 실제로는 각 메서드를 구분할 수 없습니다.
    // 간단하게 "method_call"로 처리하거나, 인자로 메서드 이름을 전달해야 합니다.
    std::string methodName = "unknown_method";

    // Collect arguments
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i) {
        const char* arg_str = JS_ToCString(ctx, argv[i]);
        if (arg_str) {
            args.push_back(std::string(arg_str));
            JS_FreeCString(ctx, arg_str);
        } else {
            args.push_back("[complex object]");
        }
    }

    // Analyze the method call
    axObj->analyzeMethodCall(methodName, args);

    // Return mock response
    std::string mockResponse = axObj->generateMockResponse(methodName);
    return JS_NewString(ctx, mockResponse.c_str());
}

JSValue ActiveXObject::js_property_get(JSContext* ctx, JSValueConst this_val, JSAtom prop) {
    ActiveXObject* axObj = getThis(ctx, this_val);
    if (!axObj) {
        return JS_EXCEPTION;
    }

    const char* prop_str = JS_AtomToCString(ctx, prop);
    if (!prop_str) {
        return JS_UNDEFINED;
    }

    std::string propName(prop_str);
    JS_FreeCString(ctx, prop_str);

    auto it = axObj->properties.find(propName);
    if (it != axObj->properties.end()) {
        return JS_DupValue(ctx, it->second);
    }

    // Return mock property values
    if (propName == "Status" || propName == "status") {
        return JS_NewInt32(ctx, 200);
    }
    if (propName == "StatusText" || propName == "statusText") {
        return JS_NewString(ctx, "OK");
    }
    if (propName == "ResponseText" || propName == "responseText") {
        return JS_NewString(ctx, "[Mock Response]");
    }
    if (propName == "ReadyState" || propName == "readyState") {
        return JS_NewInt32(ctx, 4);
    }

    return JS_UNDEFINED;
}

JSValue ActiveXObject::js_property_set(JSContext* ctx, JSValueConst this_val, JSAtom prop, JSValueConst val) {
    ActiveXObject* axObj = getThis(ctx, this_val);
    if (!axObj) {
        return JS_EXCEPTION;
    }

    const char* prop_str = JS_AtomToCString(ctx, prop);
    if (!prop_str) {
        return JS_UNDEFINED;
    }

    std::string propName(prop_str);
    JS_FreeCString(ctx, prop_str);

    // Store the property value
    auto it = axObj->properties.find(propName);
    if (it != axObj->properties.end()) {
        JS_FreeValue(ctx, it->second);
    }
    axObj->properties[propName] = JS_DupValue(ctx, val);

    // Track property assignment
    if (axObj->a_ctx && axObj->a_ctx->chainTrackerManager) {
        const char* val_str = JS_ToCString(ctx, val);
        std::string valString = val_str ? std::string(val_str) : "[complex value]";
        if (val_str) JS_FreeCString(ctx, val_str);

        axObj->a_ctx->chainTrackerManager->trackFunctionCall(
            axObj->progID + "." + propName + " = ",
            {JsValue(valString)},
            JsValue(std::monostate())
        );
    }

    return JS_UNDEFINED;
}

// 각 메서드별 핸들러 함수들
JSValue ActiveXObject::js_run(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    ActiveXObject* axObj = getThis(ctx, this_val);
    if (!axObj) return JS_EXCEPTION;
    
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i) {
        const char* arg_str = JS_ToCString(ctx, argv[i]);
        if (arg_str) {
            args.push_back(std::string(arg_str));
            JS_FreeCString(ctx, arg_str);
        }
    }
    
    axObj->analyzeMethodCall("Run", args);
    return JS_NewString(ctx, axObj->generateMockResponse("Run").c_str());
}

JSValue ActiveXObject::js_exec(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    ActiveXObject* axObj = getThis(ctx, this_val);
    if (!axObj) return JS_EXCEPTION;
    
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i) {
        const char* arg_str = JS_ToCString(ctx, argv[i]);
        if (arg_str) {
            args.push_back(std::string(arg_str));
            JS_FreeCString(ctx, arg_str);
        }
    }
    
    axObj->analyzeMethodCall("Exec", args);
    return JS_NewString(ctx, axObj->generateMockResponse("Exec").c_str());
}

JSValue ActiveXObject::js_createTextFile(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    ActiveXObject* axObj = getThis(ctx, this_val);
    if (!axObj) return JS_EXCEPTION;
    
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i) {
        const char* arg_str = JS_ToCString(ctx, argv[i]);
        if (arg_str) {
            args.push_back(std::string(arg_str));
            JS_FreeCString(ctx, arg_str);
        }
    }
    
    axObj->analyzeMethodCall("CreateTextFile", args);
    return JS_NewString(ctx, axObj->generateMockResponse("CreateTextFile").c_str());
}

JSValue ActiveXObject::js_openTextFile(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    ActiveXObject* axObj = getThis(ctx, this_val);
    if (!axObj) return JS_EXCEPTION;
    
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i) {
        const char* arg_str = JS_ToCString(ctx, argv[i]);
        if (arg_str) {
            args.push_back(std::string(arg_str));
            JS_FreeCString(ctx, arg_str);
        }
    }
    
    axObj->analyzeMethodCall("OpenTextFile", args);
    return JS_NewString(ctx, axObj->generateMockResponse("OpenTextFile").c_str());
}

JSValue ActiveXObject::js_deleteFile(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    ActiveXObject* axObj = getThis(ctx, this_val);
    if (!axObj) return JS_EXCEPTION;
    
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i) {
        const char* arg_str = JS_ToCString(ctx, argv[i]);
        if (arg_str) {
            args.push_back(std::string(arg_str));
            JS_FreeCString(ctx, arg_str);
        }
    }
    
    axObj->analyzeMethodCall("DeleteFile", args);
    return JS_NewString(ctx, axObj->generateMockResponse("DeleteFile").c_str());
}

JSValue ActiveXObject::js_send(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    ActiveXObject* axObj = getThis(ctx, this_val);
    if (!axObj) return JS_EXCEPTION;
    
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i) {
        const char* arg_str = JS_ToCString(ctx, argv[i]);
        if (arg_str) {
            args.push_back(std::string(arg_str));
            JS_FreeCString(ctx, arg_str);
        }
    }
    
    axObj->analyzeMethodCall("Send", args);
    return JS_NewString(ctx, axObj->generateMockResponse("Send").c_str());
}

JSValue ActiveXObject::js_open(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    ActiveXObject* axObj = getThis(ctx, this_val);
    if (!axObj) return JS_EXCEPTION;
    
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i) {
        const char* arg_str = JS_ToCString(ctx, argv[i]);
        if (arg_str) {
            args.push_back(std::string(arg_str));
            JS_FreeCString(ctx, arg_str);
        }
    }
    
    axObj->analyzeMethodCall("Open", args);
    return JS_NewString(ctx, axObj->generateMockResponse("Open").c_str());
}

// ============================================
// 🔥 QuickJS 등록 함수 (JSAnalyzer에서 호출)
// ============================================

// Finalizer
static void activex_finalizer(JSRuntime* rt, JSValue val) {
    struct RuntimeClassIDs {
        JSClassID xhr_class_id;
        JSClassID activex_class_id;
    };
    
    RuntimeClassIDs* classIDs = static_cast<RuntimeClassIDs*>(JS_GetRuntimeOpaque(rt));
    if (!classIDs) return;
    
    ActiveXObject* axObj = static_cast<ActiveXObject*>(
        JS_GetOpaque(val, classIDs->activex_class_id)
    );
    if (axObj) {
        axObj->ctx = nullptr;
        delete axObj;
    }
}

// 통합 등록 함수
void ActiveXObject::registerClass(JSContext* ctx, JSRuntime* rt, JSValue global_obj, JSClassID class_id) {
    // 클래스 정의
    JSClassDef js_activex_class = {
        .class_name = "ActiveXObject",
        .finalizer = activex_finalizer,
    };
    JS_NewClass(rt, class_id, &js_activex_class);
    
    // Constructor 생성 및 등록
    JSValue activex_constructor_func = JS_NewCFunction2(ctx, ActiveXObject::js_constructor, 
                                                         "ActiveXObject", 1, 
                                                         JS_CFUNC_constructor, 0);
    JS_SetPropertyStr(ctx, global_obj, "ActiveXObject", activex_constructor_func);
}
