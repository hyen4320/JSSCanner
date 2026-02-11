#include "pch.h"
#include "MockHelpers.h"
#include "SensitiveKeywordDetector.h"
#include <sstream>
#include <algorithm>

// 전방 선언
namespace ElementObject {
    JSValue js_element_addEventListener(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_element_setAttribute(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_element_getAttribute(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_element_hasAttribute(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_element_removeAttribute(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_element_appendChild(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
}

namespace MockHelpers {
    std::set<std::string> parseClassTokens(const std::string& tokenStr) {
        std::set<std::string> tokens;
        std::istringstream iss(tokenStr);
        std::string token;
        while (iss >> token) {
            tokens.insert(token);
        }
        return tokens;
    }

    std::string joinClassTokens(const std::set<std::string>& tokens) {
        std::string result;
        for (auto it = tokens.begin(); it != tokens.end(); ++it) {
            if (it != tokens.begin()) {
                result += " ";
            }
            result += *it;
        }
        return result;
    }

    void classListAddToken(JSContext* ctx, JSValue classList, const std::string& token) {
        if (token.empty()) {
            JS_FreeValue(ctx, classList);
            return;
        }

        JSValue tokens_val = JS_GetPropertyStr(ctx, classList, "_tokens");
        std::string current;
        if (!JS_IsUndefined(tokens_val) && !JS_IsNull(tokens_val)) {
            const char* str = JS_ToCString(ctx, tokens_val);
            if (str) {
                current = str;
                JS_FreeCString(ctx, str);
            }
        }
        JS_FreeValue(ctx, tokens_val);

        std::set<std::string> tokens = parseClassTokens(current);
        tokens.insert(token);
        JS_SetPropertyStr(ctx, classList, "_tokens", JS_NewString(ctx, joinClassTokens(tokens).c_str()));
        JS_FreeValue(ctx, classList);
    }

    JSValue createClassListObject(JSContext* ctx) {
        // classList 메서드들은 ElementObject에서 제공
        JSValue classList = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, classList, "_tokens", JS_NewString(ctx, ""));
        return classList;
    }

    JSValue createStyleObject(JSContext* ctx) {
        JSValue style = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, style, "display", JS_NewString(ctx, "none"));
        JS_SetPropertyStr(ctx, style, "visibility", JS_NewString(ctx, "visible"));
        JS_SetPropertyStr(ctx, style, "position", JS_NewString(ctx, "static"));
        return style;
    }

    void setElementStringProperty(JSContext* ctx, JSValue element, const char* name, const std::string& value) {
        JS_SetPropertyStr(ctx, element, name, JS_NewString(ctx, value.c_str()));
    }

    static void ensureAttributeStore(JSContext* ctx, JSValue element) {
        JSValue attrs = JS_GetPropertyStr(ctx, element, "__attributes");
        if (!JS_IsUndefined(attrs) && !JS_IsNull(attrs)) {
            JS_FreeValue(ctx, attrs);
            return;
        }
        JS_FreeValue(ctx, attrs);
        JS_SetPropertyStr(ctx, element, "__attributes", JS_NewObject(ctx));
    }

    void setMockAttribute(JSContext* ctx, JSValue element, const std::string& name, const std::string& value) {
        JSValue elementDup = JS_DupValue(ctx, element);
        ensureAttributeStore(ctx, elementDup);
        JSValue attrs = JS_GetPropertyStr(ctx, elementDup, "__attributes");
        if (JS_IsException(attrs)) {
            JS_FreeValue(ctx, elementDup);
            return;
        }
        JS_SetPropertyStr(ctx, attrs, name.c_str(), JS_NewString(ctx, value.c_str()));
        JS_FreeValue(ctx, attrs);
        JS_FreeValue(ctx, elementDup);
    }

    std::string getDefaultElementValue(const std::string& id) {
        std::string lower = SensitiveKeywordDetector::toLower(id);
        if (lower.find("username") != std::string::npos || lower.find("email") != std::string::npos) {
            return "user@example.com";
        }
        if (lower.find("password") != std::string::npos) {
            return "P@ssw0rd!";
        }
        if (lower.find("token") != std::string::npos) {
            return "123456";
        }
        if (lower.find("subdomain") != std::string::npos) {
            return "corp";
        }
        if (lower.find("organization") != std::string::npos) {
            return "storedcorp";
        }
        return "";
    }

    std::string getDefaultElementText(const std::string& id) {
        std::string lower = SensitiveKeywordDetector::toLower(id);
        if (lower.find("options") != std::string::npos) {
            return ".okta.com";
        }
        if (lower.find("emaildisplay") != std::string::npos) {
            return "user@example.com";
        }
        return "";
    }

    static JSValue js_event_preventDefault(JSContext* ctx, JSValueConst, int, JSValueConst*) {
        return JS_UNDEFINED;
    }

    static JSValue js_event_stopPropagation(JSContext* ctx, JSValueConst, int, JSValueConst*) {
        return JS_UNDEFINED;
    }

    JSValue createEventObject(JSContext* ctx, JSValueConst currentTarget, const std::string& eventName, JSValue targetOverride) {
        JSValue eventObj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, eventObj, "type", JS_NewString(ctx, eventName.c_str()));
        JS_SetPropertyStr(ctx, eventObj, "preventDefault", JS_NewCFunction(ctx, js_event_preventDefault, "preventDefault", 0));
        JS_SetPropertyStr(ctx, eventObj, "stopPropagation", JS_NewCFunction(ctx, js_event_stopPropagation, "stopPropagation", 0));

        JSValue current = JS_DupValue(ctx, currentTarget);
        JS_SetPropertyStr(ctx, eventObj, "currentTarget", current);

        if (!JS_IsUndefined(targetOverride)) {
            JS_SetPropertyStr(ctx, eventObj, "target", targetOverride);
        } else {
            JS_SetPropertyStr(ctx, eventObj, "target", JS_DupValue(ctx, currentTarget));
        }

        if (eventName == "keypress") {
            JS_SetPropertyStr(ctx, eventObj, "key", JS_NewString(ctx, "Enter"));
        }

        return eventObj;
    }

    JSValue createMockElement(JSContext* ctx, const std::string& id) {
        JSValue obj = JS_NewObject(ctx);

        setElementStringProperty(ctx, obj, "id", id);
        JS_SetPropertyStr(ctx, obj, "__attributes", JS_NewObject(ctx));
        JS_SetPropertyStr(ctx, obj, "classList", createClassListObject(ctx));
        JS_SetPropertyStr(ctx, obj, "style", createStyleObject(ctx));
        JS_SetPropertyStr(ctx, obj, "dataset", JS_NewObject(ctx));

        // ElementObject의 함수들을 사용
        JS_SetPropertyStr(ctx, obj, "addEventListener", 
            JS_NewCFunction(ctx, ElementObject::js_element_addEventListener, "addEventListener", 2));
        JS_SetPropertyStr(ctx, obj, "setAttribute", 
            JS_NewCFunction(ctx, ElementObject::js_element_setAttribute, "setAttribute", 2));
        JS_SetPropertyStr(ctx, obj, "getAttribute", 
            JS_NewCFunction(ctx, ElementObject::js_element_getAttribute, "getAttribute", 1));
        JS_SetPropertyStr(ctx, obj, "hasAttribute", 
            JS_NewCFunction(ctx, ElementObject::js_element_hasAttribute, "hasAttribute", 1));
        JS_SetPropertyStr(ctx, obj, "removeAttribute", 
            JS_NewCFunction(ctx, ElementObject::js_element_removeAttribute, "removeAttribute", 1));
        JS_SetPropertyStr(ctx, obj, "appendChild", 
            JS_NewCFunction(ctx, ElementObject::js_element_appendChild, "appendChild", 1));
        JS_SetPropertyStr(ctx, obj, "focus", JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst, int, JSValueConst*) {
            return JS_UNDEFINED;
        }, "focus", 0));

        setElementStringProperty(ctx, obj, "innerHTML", "");
        setElementStringProperty(ctx, obj, "outerHTML", "");
        setElementStringProperty(ctx, obj, "title", "");
        setElementStringProperty(ctx, obj, "className", "");

        std::string defaultText = getDefaultElementText(id);
        std::string defaultValue = getDefaultElementValue(id);

        setElementStringProperty(ctx, obj, "textContent", defaultText);
        setElementStringProperty(ctx, obj, "value", defaultValue);

        JS_SetPropertyStr(ctx, obj, "disabled", JS_NewBool(ctx, 0));

        return obj;
    }
}
