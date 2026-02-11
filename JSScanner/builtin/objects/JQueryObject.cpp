#include "pch.h"
#include "JQueryObject.h"
#include "../helpers/JSValueConverter.h"
#include "../../model/JsValueVariant.h"
#include "../../core/JSAnalyzer.h"
#include "../../hooks/HookType.h"

namespace JQueryObject {
    // Forward declaration
    JSValue createJQueryObject(JSContext* ctx, const char* selector);

    static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
        return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
    }

    // ==================== AJAX 메서드 ====================

    JSValue js_ajax(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        std::string url = "";
        std::string method = "GET";
        std::string data = "";

        if (argc >= 1 && JS_IsObject(argv[0])) {
            JSValue url_val = JS_GetPropertyStr(ctx, argv[0], "url");
            if (!JS_IsUndefined(url_val)) {
                url = JSValueConverter::toString(ctx, url_val);
            }
            JS_FreeValue(ctx, url_val);

            JSValue method_val = JS_GetPropertyStr(ctx, argv[0], "type");
            if (JS_IsUndefined(method_val)) {
                method_val = JS_GetPropertyStr(ctx, argv[0], "method");
            }
            if (!JS_IsUndefined(method_val)) {
                method = JSValueConverter::toString(ctx, method_val);
            }
            JS_FreeValue(ctx, method_val);

            JSValue data_val = JS_GetPropertyStr(ctx, argv[0], "data");
            if (!JS_IsUndefined(data_val)) {
                data = JSValueConverter::toString(ctx, data_val);
            }
            JS_FreeValue(ctx, data_val);
        }

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            std::map<std::string, JsValue> metadata;
            metadata["url"] = JsValue(url);
            metadata["method"] = JsValue(method);
            if (!data.empty()) {
                metadata["body"] = JsValue(data);
            }

            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::FETCH_REQUEST,
                "$.ajax",
                { JsValue(url), JsValue(method) },
                JsValue(std::monostate()),
                metadata,
                5
            });
        }

        // Mock Promise 반환
        JSValue promise = JS_NewObject(ctx);
        JSValue then_func = JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
            return this_val;
        }, "then", 1);
        JS_SetPropertyStr(ctx, promise, "then", then_func);
        return promise;
    }

    JSValue js_get(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        std::string url = argc >= 1 ? JSValueConverter::toString(ctx, argv[0]) : "";

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            std::map<std::string, JsValue> metadata;
            metadata["url"] = JsValue(url);
            metadata["method"] = JsValue("GET");

            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::FETCH_REQUEST,
                "$.get",
                { JsValue(url) },
                JsValue(std::monostate()),
                metadata,
                4
            });
        }

        JSValue promise = JS_NewObject(ctx);
        JSValue then_func = JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
            return this_val;
        }, "then", 1);
        JS_SetPropertyStr(ctx, promise, "then", then_func);
        return promise;
    }

    JSValue js_post(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        std::string url = argc >= 1 ? JSValueConverter::toString(ctx, argv[0]) : "";
        std::string data = argc >= 2 ? JSValueConverter::toString(ctx, argv[1]) : "";

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            std::map<std::string, JsValue> metadata;
            metadata["url"] = JsValue(url);
            metadata["method"] = JsValue("POST");
            if (!data.empty()) {
                metadata["body"] = JsValue(data);
            }

            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::FETCH_REQUEST,
                "$.post",
                { JsValue(url), JsValue(data) },
                JsValue(std::monostate()),
                metadata,
                5
            });
        }

        JSValue promise = JS_NewObject(ctx);
        JSValue then_func = JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
            return this_val;
        }, "then", 1);
        JS_SetPropertyStr(ctx, promise, "then", then_func);
        return promise;
    }

    // ==================== DOM 조작 메서드 ====================

    JSValue js_html(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        if (argc >= 1) {
            // Setter
            std::string content = JSValueConverter::toString(ctx, argv[0]);

            if (a_ctx && a_ctx->dynamicAnalyzer) {
                // Severity 계산 - HTML 주입의 위험도 기반
                int severity = 0;
                std::map<std::string, JsValue> metadata;
                
                std::string lowerContent = content;
                std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);
                
                // 위험한 태그 감지
                bool hasScript = lowerContent.find("<script") != std::string::npos;
                bool hasIframe = lowerContent.find("<iframe") != std::string::npos;
                bool hasObject = lowerContent.find("<object") != std::string::npos;
                bool hasEmbed = lowerContent.find("<embed") != std::string::npos;
                
                if (hasScript || hasIframe || hasObject || hasEmbed) {
                    severity += 3;
                    metadata["contains_dangerous_tags"] = JsValue("true");
                }
                
                // 외부 URL 감지
                if (content.find("http://") != std::string::npos || content.find("https://") != std::string::npos) {
                    severity += 1;
                    metadata["contains_url"] = JsValue("true");
                }
                
                a_ctx->dynamicAnalyzer->recordEvent({
                    HookType::DOM_MANIPULATION,
                    "$.html",
                    { JsValue(content) },
                    JsValue(std::monostate()),
                    metadata,
                    severity
                });
            }
        }

        // 체이닝을 위해 this 반환
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_append(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        if (argc >= 1) {
            std::string content = JSValueConverter::toString(ctx, argv[0]);

            if (a_ctx && a_ctx->dynamicAnalyzer) {
                // Severity 계산 - HTML 주입의 위험도 기반
                int severity = 0;
                std::map<std::string, JsValue> metadata;
                
                std::string lowerContent = content;
                std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);
                
                // 위험한 태그 감지
                if (lowerContent.find("<script") != std::string::npos ||
                    lowerContent.find("<iframe") != std::string::npos ||
                    lowerContent.find("<object") != std::string::npos ||
                    lowerContent.find("<embed") != std::string::npos) {
                    severity += 3;
                    metadata["contains_dangerous_tags"] = JsValue("true");
                }
                
                // 외부 URL 감지
                if (content.find("http://") != std::string::npos || content.find("https://") != std::string::npos) {
                    severity += 1;
                }
                
                a_ctx->dynamicAnalyzer->recordEvent({
                    HookType::DOM_MANIPULATION,
                    "$.append",
                    { JsValue(content) },
                    JsValue(std::monostate()),
                    metadata,
                    severity
                });
            }
        }

        return JS_DupValue(ctx, this_val);
    }

    JSValue js_text(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        if (argc >= 1) {
            std::string content = JSValueConverter::toString(ctx, argv[0]);

            if (a_ctx && a_ctx->dynamicAnalyzer) {
                a_ctx->dynamicAnalyzer->recordEvent({
                    HookType::DOM_MANIPULATION,
                    "$.text",
                    { JsValue(content) },
                    JsValue(std::monostate()),
                    {},
                    3
                });
            }
        }

        return JS_DupValue(ctx, this_val);
    }

    JSValue js_remove(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::DOM_MANIPULATION,
                "$.remove",
                {},
                JsValue(std::monostate()),
                {},
                4
            });
        }

        return JS_DupValue(ctx, this_val);
    }

    JSValue js_prepend(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        if (argc >= 1) {
            std::string content = JSValueConverter::toString(ctx, argv[0]);

            if (a_ctx && a_ctx->dynamicAnalyzer) {
                a_ctx->dynamicAnalyzer->recordEvent({
                    HookType::DOM_MANIPULATION,
                    "$.prepend",
                    { JsValue(content) },
                    JsValue(std::monostate()),
                    {},
                    6
                });
            }
        }

        return JS_DupValue(ctx, this_val);
    }

    JSValue js_after(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        if (argc >= 1) {
            std::string content = JSValueConverter::toString(ctx, argv[0]);

            if (a_ctx && a_ctx->dynamicAnalyzer) {
                a_ctx->dynamicAnalyzer->recordEvent({
                    HookType::DOM_MANIPULATION,
                    "$.after",
                    { JsValue(content) },
                    JsValue(std::monostate()),
                    {},
                    5
                });
            }
        }

        return JS_DupValue(ctx, this_val);
    }

    JSValue js_before(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        if (argc >= 1) {
            std::string content = JSValueConverter::toString(ctx, argv[0]);

            if (a_ctx && a_ctx->dynamicAnalyzer) {
                a_ctx->dynamicAnalyzer->recordEvent({
                    HookType::DOM_MANIPULATION,
                    "$.before",
                    { JsValue(content) },
                    JsValue(std::monostate()),
                    {},
                    5
                });
            }
        }

        return JS_DupValue(ctx, this_val);
    }

    JSValue js_replaceWith(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        if (argc >= 1) {
            std::string content = JSValueConverter::toString(ctx, argv[0]);

            if (a_ctx && a_ctx->dynamicAnalyzer) {
                a_ctx->dynamicAnalyzer->recordEvent({
                    HookType::DOM_MANIPULATION,
                    "$.replaceWith",
                    { JsValue(content) },
                    JsValue(std::monostate()),
                    {},
                    6
                });
            }
        }

        return JS_DupValue(ctx, this_val);
    }

    JSValue js_wrap(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_unwrap(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_clone(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "cloned");
    }

    JSValue js_empty(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::DOM_MANIPULATION,
                "$.empty",
                {},
                JsValue(std::monostate()),
                {},
                3
            });
        }

        return JS_DupValue(ctx, this_val);
    }

    JSValue js_detach(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_DupValue(ctx, this_val);
    }

    // ==================== 이벤트 메서드 ====================

    JSValue js_on(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        std::string eventName = argc >= 1 ? JSValueConverter::toString(ctx, argv[0]) : "";

        if (argc >= 2 && JS_IsFunction(ctx, argv[1])) {
            // 콜백 즉시 실행
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[1], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::FUNCTION_CALL,
                "$.on",
                { JsValue(eventName) },
                JsValue(std::monostate()),
                {},
                2
            });
        }

        return JS_DupValue(ctx, this_val);
    }

    JSValue js_click(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            // 콜백 즉시 실행
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::FUNCTION_CALL,
                "$.click",
                {},
                JsValue(std::monostate()),
                {},
                2
            });
        }

        return JS_DupValue(ctx, this_val);
    }

    JSValue js_ready(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        // 🔥 콜백 실행을 제거 - 사용자 콜백 내부에서 크래시 발생 가능성이 높음
        // document ready는 로깅만 수행하고 실제 실행은 하지 않음
        // 분석 목적으로는 콜백이 등록되었다는 사실만 기록하면 충분

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::FUNCTION_CALL,
                "$.ready",
                {},
                JsValue(std::monostate()),
                {},
                1
            });
        }

        return JS_UNDEFINED;
    }

    // ==================== CSS/속성 메서드 ====================

    JSValue js_css(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 2) {
            // Setter
            std::string prop = JSValueConverter::toString(ctx, argv[0]);
            std::string value = JSValueConverter::toString(ctx, argv[1]);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_addClass(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_removeClass(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_toggleClass(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_attr(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 2) {
            std::string attr = JSValueConverter::toString(ctx, argv[0]);
            std::string value = JSValueConverter::toString(ctx, argv[1]);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_prop(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 2) {
            return JS_DupValue(ctx, this_val);
        }
        return JS_UNDEFINED;
    }

    JSValue js_data(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 2) {
            return JS_DupValue(ctx, this_val);
        }
        return JS_UNDEFINED;
    }

    JSValue js_val(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        if (argc >= 1) {
            std::string value = JSValueConverter::toString(ctx, argv[0]);

            if (a_ctx && a_ctx->dynamicAnalyzer) {
                a_ctx->dynamicAnalyzer->recordEvent({
                    HookType::DOM_MANIPULATION,
                    "$.val",
                    { JsValue(value) },
                    JsValue(std::monostate()),
                    {},
                    3
                });
            }
            return JS_DupValue(ctx, this_val);
        }
        return JS_NewString(ctx, "");
    }

    JSValue js_hasClass(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_NewBool(ctx, 0);
    }

    JSValue js_removeAttr(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_removeProp(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_DupValue(ctx, this_val);
    }

    // ==================== 트래버싱 메서드 ====================

    JSValue js_find(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        std::string selector = argc >= 1 ? JSValueConverter::toString(ctx, argv[0]) : "";
        return createJQueryObject(ctx, selector.c_str());
    }

    JSValue js_parent(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "parent");
    }

    JSValue js_parents(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "parents");
    }

    JSValue js_children(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "children");
    }

    JSValue js_siblings(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "siblings");
    }

    JSValue js_next(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "next");
    }

    JSValue js_prev(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "prev");
    }

    JSValue js_eq(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "eq");
    }

    JSValue js_first(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "first");
    }

    JSValue js_last(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "last");
    }

    JSValue js_filter(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return createJQueryObject(ctx, "filtered");
    }

    JSValue js_closest(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "closest");
    }

    JSValue js_nextAll(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "nextAll");
    }

    JSValue js_prevAll(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "prevAll");
    }

    JSValue js_nextUntil(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "nextUntil");
    }

    JSValue js_prevUntil(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "prevUntil");
    }

    JSValue js_parentsUntil(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "parentsUntil");
    }

    JSValue js_contents(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "contents");
    }

    JSValue js_end(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "previous");
    }

    JSValue js_addBack(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "addBack");
    }

    // ==================== 배열/컬렉션 메서드 ====================

    JSValue js_getElement(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1) {
            return JS_UNDEFINED;
        }
        return JS_NewArray(ctx);
    }

    JSValue js_toArray(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_NewArray(ctx);
    }

    JSValue js_index(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_NewInt32(ctx, 0);
    }

    JSValue js_size(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_NewInt32(ctx, 1);
    }

    JSValue js_slice(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "sliced");
    }

    JSValue js_add(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "added");
    }

    // ==================== 효과/애니메이션 메서드 ====================

    JSValue js_show(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_hide(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_toggle(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_fadeIn(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_fadeOut(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_fadeToggle(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_slideDown(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_slideUp(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_slideToggle(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_animate(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 2 && JS_IsFunction(ctx, argv[1])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[1], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    // ==================== 폼 메서드 ====================

    JSValue js_serialize(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::FUNCTION_CALL,
                "$.serialize",
                {},
                JsValue("serialized_data"),
                {},
                4
            });
        }

        return JS_NewString(ctx, "field1=value1&field2=value2");
    }

    JSValue js_serializeArray(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_NewArray(ctx);
    }

    JSValue js_submit(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::FUNCTION_CALL,
                "$.submit",
                {},
                JsValue(std::monostate()),
                {},
                3
            });
        }

        return JS_DupValue(ctx, this_val);
    }

    // ==================== 추가 AJAX 메서드 ====================

    JSValue js_load(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        std::string url = argc >= 1 ? JSValueConverter::toString(ctx, argv[0]) : "";

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            std::map<std::string, JsValue> metadata;
            metadata["url"] = JsValue(url);
            metadata["method"] = JsValue("GET");

            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::FETCH_REQUEST,
                "$.load",
                { JsValue(url) },
                JsValue(std::monostate()),
                metadata,
                5
            });
        }

        return JS_DupValue(ctx, this_val);
    }

    JSValue js_getJSON(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        std::string url = argc >= 1 ? JSValueConverter::toString(ctx, argv[0]) : "";

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            std::map<std::string, JsValue> metadata;
            metadata["url"] = JsValue(url);
            metadata["method"] = JsValue("GET");

            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::FETCH_REQUEST,
                "$.getJSON",
                { JsValue(url) },
                JsValue(std::monostate()),
                metadata,
                4
            });
        }

        JSValue promise = JS_NewObject(ctx);
        JSValue then_func = JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
            return this_val;
        }, "then", 1);
        JS_SetPropertyStr(ctx, promise, "then", then_func);
        return promise;
    }

    JSValue js_getScript(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);

        std::string url = argc >= 1 ? JSValueConverter::toString(ctx, argv[0]) : "";

        if (a_ctx && a_ctx->dynamicAnalyzer) {
            std::map<std::string, JsValue> metadata;
            metadata["url"] = JsValue(url);
            metadata["method"] = JsValue("GET");

            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::FETCH_REQUEST,
                "$.getScript",
                { JsValue(url) },
                JsValue(std::monostate()),
                metadata,
                8
            });
        }

        JSValue promise = JS_NewObject(ctx);
        JSValue then_func = JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
            return this_val;
        }, "then", 1);
        JS_SetPropertyStr(ctx, promise, "then", then_func);
        return promise;
    }

    // ==================== 추가 이벤트 메서드 ====================

    JSValue js_off(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_trigger(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_change(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_focus(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_blur(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_keypress(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_keydown(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_keyup(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_mouseenter(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_mouseleave(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_one(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 2 && JS_IsFunction(ctx, argv[1])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[1], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_hover(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        if (argc >= 2 && JS_IsFunction(ctx, argv[1])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[1], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_dblclick(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_scroll(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_resize(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_unload(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_error(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    // ==================== 추가 유틸리티 메서드 ====================

    JSValue js_map(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return createJQueryObject(ctx, "mapped");
    }

    JSValue js_is(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_NewBool(ctx, 1);
    }

    JSValue js_not(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "not");
    }

    JSValue js_has(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return createJQueryObject(ctx, "has");
    }

    // ==================== 치수/위치 메서드 ====================

    JSValue js_width(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1) {
            return JS_DupValue(ctx, this_val);
        }
        return JS_NewInt32(ctx, 0);
    }

    JSValue js_height(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1) {
            return JS_DupValue(ctx, this_val);
        }
        return JS_NewInt32(ctx, 0);
    }

    JSValue js_offset(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSValue obj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, obj, "top", JS_NewInt32(ctx, 0));
        JS_SetPropertyStr(ctx, obj, "left", JS_NewInt32(ctx, 0));
        return obj;
    }

    JSValue js_position(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSValue obj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, obj, "top", JS_NewInt32(ctx, 0));
        JS_SetPropertyStr(ctx, obj, "left", JS_NewInt32(ctx, 0));
        return obj;
    }

    JSValue js_scrollTop(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1) {
            return JS_DupValue(ctx, this_val);
        }
        return JS_NewInt32(ctx, 0);
    }

    JSValue js_scrollLeft(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1) {
            return JS_DupValue(ctx, this_val);
        }
        return JS_NewInt32(ctx, 0);
    }

    // ==================== 유틸리티 메서드 ====================

    JSValue js_each(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 2 || !JS_IsFunction(ctx, argv[1])) {
            return JS_DupValue(ctx, this_val);
        }

        JSValue arr = argv[0];
        JSValue callback = argv[1];

        JSValue len_val = JS_GetPropertyStr(ctx, arr, "length");
        int32_t len;
        if (JS_ToInt32(ctx, &len, len_val) == 0) {
            for (int32_t i = 0; i < len && i < 1000; i++) {  // 최대 1000개
                JSValue item = JS_GetPropertyUint32(ctx, arr, i);
                JSValue args[2] = { JS_NewInt32(ctx, i), item };
                JS_Call(ctx, callback, JS_UNDEFINED, 2, args);
                JS_FreeValue(ctx, args[0]);
                JS_FreeValue(ctx, item);
            }
        }
        JS_FreeValue(ctx, len_val);

        return JS_DupValue(ctx, this_val);
    }

    JSValue js_extend(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 2) return JS_NewObject(ctx);

        JSValue target = JS_DupValue(ctx, argv[0]);

        for (int i = 1; i < argc; i++) {
            if (JS_IsObject(argv[i])) {
                JSPropertyEnum* props;
                uint32_t prop_count;
                if (JS_GetOwnPropertyNames(ctx, &props, &prop_count, argv[i], JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0) {
                    for (uint32_t j = 0; j < prop_count; j++) {
                        JSValue val = JS_GetProperty(ctx, argv[i], props[j].atom);
                        JS_SetProperty(ctx, target, props[j].atom, val);
                    }
                    js_free(ctx, props);
                }
            }
        }

        return target;
    }

    JSValue js_parseJSON(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) return JS_UNDEFINED;

        std::string json_str = JSValueConverter::toString(ctx, argv[0]);
        JSValue result = JS_ParseJSON(ctx, json_str.c_str(), json_str.length(), "<parseJSON>");

        return result;
    }

    JSValue js_trim(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) return JS_NewString(ctx, "");
        std::string str = JSValueConverter::toString(ctx, argv[0]);
        // 간단한 trim
        size_t start = str.find_first_not_of(" \t\n\r");
        size_t end = str.find_last_not_of(" \t\n\r");
        if (start == std::string::npos) return JS_NewString(ctx, "");
        return JS_NewString(ctx, str.substr(start, end - start + 1).c_str());
    }

    JSValue js_type(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) return JS_NewString(ctx, "undefined");
        JSValue obj = argv[0];
        if (JS_IsNull(obj)) return JS_NewString(ctx, "null");
        if (JS_IsUndefined(obj)) return JS_NewString(ctx, "undefined");
        if (JS_IsBool(obj)) return JS_NewString(ctx, "boolean");
        if (JS_IsNumber(obj)) return JS_NewString(ctx, "number");
        if (JS_IsString(obj)) return JS_NewString(ctx, "string");
        if (JS_IsFunction(ctx, obj)) return JS_NewString(ctx, "function");
        if (JS_IsArray(argv[0])) return JS_NewString(ctx, "array");
        return JS_NewString(ctx, "object");
    }

    JSValue js_isArray(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) return JS_NewBool(ctx, 0);
        return JS_NewBool(ctx, JS_IsArray(argv[0]));
    }

    JSValue js_isFunction(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) return JS_NewBool(ctx, 0);
        return JS_NewBool(ctx, JS_IsFunction(ctx, argv[0]));
    }

    JSValue js_isNumeric(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) return JS_NewBool(ctx, 0);
        return JS_NewBool(ctx, JS_IsNumber(argv[0]));
    }

    JSValue js_isEmptyObject(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_NewBool(ctx, 0);
    }

    JSValue js_isPlainObject(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) return JS_NewBool(ctx, 0);
        return JS_NewBool(ctx, JS_IsObject(argv[0]));
    }

    JSValue js_inArray(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_NewInt32(ctx, -1);
    }

    JSValue js_grep(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 2 || !JS_IsFunction(ctx, argv[1])) {
            return JS_NewArray(ctx);
        }
        JSValue result = JS_NewArray(ctx);
        return result;
    }

    JSValue js_merge(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 2) return JS_NewArray(ctx);
        return JS_DupValue(ctx, argv[0]);
    }

    JSValue js_makeArray(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_NewArray(ctx);
    }

    JSValue js_unique(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) return JS_NewArray(ctx);
        return JS_DupValue(ctx, argv[0]);
    }

    JSValue js_globalEval(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) return JS_UNDEFINED;
        std::string code = JSValueConverter::toString(ctx, argv[0]);
        return JS_Eval(ctx, code.c_str(), code.length(), "<globalEval>", JS_EVAL_TYPE_GLOBAL);
    }

    JSValue js_noop(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_UNDEFINED;
    }

    JSValue js_now(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_NewInt64(ctx, 1000000);
    }

    // ==================== Deferred/Promise 메서드 ====================

    JSValue js_Deferred(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSValue deferred = JS_NewObject(ctx);

        JSValue promise = JS_NewObject(ctx);
        JSValue then_func = JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
            return this_val;
        }, "then", 1);
        JS_SetPropertyStr(ctx, promise, "then", then_func);
        JS_SetPropertyStr(ctx, promise, "done", JS_DupValue(ctx, then_func));
        JS_SetPropertyStr(ctx, promise, "fail", JS_DupValue(ctx, then_func));
        JS_SetPropertyStr(ctx, promise, "always", JS_DupValue(ctx, then_func));

        JS_SetPropertyStr(ctx, deferred, "promise", promise);
        JS_SetPropertyStr(ctx, deferred, "resolve", JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
            return this_val;
        }, "resolve", 1));
        JS_SetPropertyStr(ctx, deferred, "reject", JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
            return this_val;
        }, "reject", 1));
        JS_SetPropertyStr(ctx, deferred, "notify", JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
            return this_val;
        }, "notify", 1));

        return deferred;
    }

    JSValue js_when(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSValue promise = JS_NewObject(ctx);
        JSValue then_func = JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
            if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
                JSValue global_obj = JS_GetGlobalObject(ctx);
                JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

                if (JS_IsException(ret)) {

                    JSValue ex = JS_GetException(ctx);

                    JS_FreeValue(ctx, ex);

                } else {

                    JS_FreeValue(ctx, ret);

                }

                JS_FreeValue(ctx, global_obj);
            }
            return this_val;
        }, "then", 1);
        JS_SetPropertyStr(ctx, promise, "then", then_func);
        JS_SetPropertyStr(ctx, promise, "done", JS_DupValue(ctx, then_func));
        JS_SetPropertyStr(ctx, promise, "fail", JS_DupValue(ctx, then_func));
        return promise;
    }

    JSValue js_promise(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        JSValue promise = JS_NewObject(ctx);
        JSValue then_func = JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
            return this_val;
        }, "then", 1);
        JS_SetPropertyStr(ctx, promise, "then", then_func);
        return promise;
    }

    JSValue js_then(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_done(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_fail(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_DupValue(ctx, this_val);
    }

    JSValue js_always(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc >= 1 && JS_IsFunction(ctx, argv[0])) {
            JSValue global_obj = JS_GetGlobalObject(ctx);
            JSValue ret = JS_Call(ctx, argv[0], global_obj, 0, NULL);

            if (JS_IsException(ret)) {

                JSValue ex = JS_GetException(ctx);

                JS_FreeValue(ctx, ex);

            } else {

                JS_FreeValue(ctx, ret);

            }

            JS_FreeValue(ctx, global_obj);
        }
        return JS_DupValue(ctx, this_val);
    }

    // ==================== jQuery 객체 생성 ====================

    JSValue createJQueryObject(JSContext* ctx, const char* selector) {
        JSValue jq_obj = JS_NewObject(ctx);

        // selector 저장
        JS_SetPropertyStr(ctx, jq_obj, "_selector", JS_NewString(ctx, selector));

        // DOM 조작 메서드
        JS_SetPropertyStr(ctx, jq_obj, "html", JS_NewCFunction(ctx, js_html, "html", 1));
        JS_SetPropertyStr(ctx, jq_obj, "append", JS_NewCFunction(ctx, js_append, "append", 1));
        JS_SetPropertyStr(ctx, jq_obj, "text", JS_NewCFunction(ctx, js_text, "text", 1));
        JS_SetPropertyStr(ctx, jq_obj, "remove", JS_NewCFunction(ctx, js_remove, "remove", 0));
        JS_SetPropertyStr(ctx, jq_obj, "prepend", JS_NewCFunction(ctx, js_prepend, "prepend", 1));
        JS_SetPropertyStr(ctx, jq_obj, "after", JS_NewCFunction(ctx, js_after, "after", 1));
        JS_SetPropertyStr(ctx, jq_obj, "before", JS_NewCFunction(ctx, js_before, "before", 1));
        JS_SetPropertyStr(ctx, jq_obj, "replaceWith", JS_NewCFunction(ctx, js_replaceWith, "replaceWith", 1));
        JS_SetPropertyStr(ctx, jq_obj, "wrap", JS_NewCFunction(ctx, js_wrap, "wrap", 1));
        JS_SetPropertyStr(ctx, jq_obj, "unwrap", JS_NewCFunction(ctx, js_unwrap, "unwrap", 0));
        JS_SetPropertyStr(ctx, jq_obj, "clone", JS_NewCFunction(ctx, js_clone, "clone", 0));
        JS_SetPropertyStr(ctx, jq_obj, "empty", JS_NewCFunction(ctx, js_empty, "empty", 0));
        JS_SetPropertyStr(ctx, jq_obj, "detach", JS_NewCFunction(ctx, js_detach, "detach", 0));

        // CSS/속성 메서드
        JS_SetPropertyStr(ctx, jq_obj, "css", JS_NewCFunction(ctx, js_css, "css", 2));
        JS_SetPropertyStr(ctx, jq_obj, "addClass", JS_NewCFunction(ctx, js_addClass, "addClass", 1));
        JS_SetPropertyStr(ctx, jq_obj, "removeClass", JS_NewCFunction(ctx, js_removeClass, "removeClass", 1));
        JS_SetPropertyStr(ctx, jq_obj, "toggleClass", JS_NewCFunction(ctx, js_toggleClass, "toggleClass", 1));
        JS_SetPropertyStr(ctx, jq_obj, "attr", JS_NewCFunction(ctx, js_attr, "attr", 2));
        JS_SetPropertyStr(ctx, jq_obj, "prop", JS_NewCFunction(ctx, js_prop, "prop", 2));
        JS_SetPropertyStr(ctx, jq_obj, "data", JS_NewCFunction(ctx, js_data, "data", 2));
        JS_SetPropertyStr(ctx, jq_obj, "val", JS_NewCFunction(ctx, js_val, "val", 1));
        JS_SetPropertyStr(ctx, jq_obj, "hasClass", JS_NewCFunction(ctx, js_hasClass, "hasClass", 1));
        JS_SetPropertyStr(ctx, jq_obj, "removeAttr", JS_NewCFunction(ctx, js_removeAttr, "removeAttr", 1));
        JS_SetPropertyStr(ctx, jq_obj, "removeProp", JS_NewCFunction(ctx, js_removeProp, "removeProp", 1));

        // 트래버싱 메서드
        JS_SetPropertyStr(ctx, jq_obj, "find", JS_NewCFunction(ctx, js_find, "find", 1));
        JS_SetPropertyStr(ctx, jq_obj, "parent", JS_NewCFunction(ctx, js_parent, "parent", 0));
        JS_SetPropertyStr(ctx, jq_obj, "parents", JS_NewCFunction(ctx, js_parents, "parents", 0));
        JS_SetPropertyStr(ctx, jq_obj, "children", JS_NewCFunction(ctx, js_children, "children", 0));
        JS_SetPropertyStr(ctx, jq_obj, "siblings", JS_NewCFunction(ctx, js_siblings, "siblings", 0));
        JS_SetPropertyStr(ctx, jq_obj, "next", JS_NewCFunction(ctx, js_next, "next", 0));
        JS_SetPropertyStr(ctx, jq_obj, "prev", JS_NewCFunction(ctx, js_prev, "prev", 0));
        JS_SetPropertyStr(ctx, jq_obj, "eq", JS_NewCFunction(ctx, js_eq, "eq", 1));
        JS_SetPropertyStr(ctx, jq_obj, "first", JS_NewCFunction(ctx, js_first, "first", 0));
        JS_SetPropertyStr(ctx, jq_obj, "last", JS_NewCFunction(ctx, js_last, "last", 0));
        JS_SetPropertyStr(ctx, jq_obj, "filter", JS_NewCFunction(ctx, js_filter, "filter", 1));
        JS_SetPropertyStr(ctx, jq_obj, "closest", JS_NewCFunction(ctx, js_closest, "closest", 1));
        JS_SetPropertyStr(ctx, jq_obj, "nextAll", JS_NewCFunction(ctx, js_nextAll, "nextAll", 0));
        JS_SetPropertyStr(ctx, jq_obj, "prevAll", JS_NewCFunction(ctx, js_prevAll, "prevAll", 0));
        JS_SetPropertyStr(ctx, jq_obj, "nextUntil", JS_NewCFunction(ctx, js_nextUntil, "nextUntil", 1));
        JS_SetPropertyStr(ctx, jq_obj, "prevUntil", JS_NewCFunction(ctx, js_prevUntil, "prevUntil", 1));
        JS_SetPropertyStr(ctx, jq_obj, "parentsUntil", JS_NewCFunction(ctx, js_parentsUntil, "parentsUntil", 1));
        JS_SetPropertyStr(ctx, jq_obj, "contents", JS_NewCFunction(ctx, js_contents, "contents", 0));
        JS_SetPropertyStr(ctx, jq_obj, "end", JS_NewCFunction(ctx, js_end, "end", 0));
        JS_SetPropertyStr(ctx, jq_obj, "addBack", JS_NewCFunction(ctx, js_addBack, "addBack", 0));

        // 효과/애니메이션 메서드
        JS_SetPropertyStr(ctx, jq_obj, "show", JS_NewCFunction(ctx, js_show, "show", 0));
        JS_SetPropertyStr(ctx, jq_obj, "hide", JS_NewCFunction(ctx, js_hide, "hide", 0));
        JS_SetPropertyStr(ctx, jq_obj, "toggle", JS_NewCFunction(ctx, js_toggle, "toggle", 0));
        JS_SetPropertyStr(ctx, jq_obj, "fadeIn", JS_NewCFunction(ctx, js_fadeIn, "fadeIn", 1));
        JS_SetPropertyStr(ctx, jq_obj, "fadeOut", JS_NewCFunction(ctx, js_fadeOut, "fadeOut", 1));
        JS_SetPropertyStr(ctx, jq_obj, "fadeToggle", JS_NewCFunction(ctx, js_fadeToggle, "fadeToggle", 0));
        JS_SetPropertyStr(ctx, jq_obj, "slideDown", JS_NewCFunction(ctx, js_slideDown, "slideDown", 1));
        JS_SetPropertyStr(ctx, jq_obj, "slideUp", JS_NewCFunction(ctx, js_slideUp, "slideUp", 1));
        JS_SetPropertyStr(ctx, jq_obj, "slideToggle", JS_NewCFunction(ctx, js_slideToggle, "slideToggle", 0));
        JS_SetPropertyStr(ctx, jq_obj, "animate", JS_NewCFunction(ctx, js_animate, "animate", 2));

        // 폼 메서드
        JS_SetPropertyStr(ctx, jq_obj, "serialize", JS_NewCFunction(ctx, js_serialize, "serialize", 0));
        JS_SetPropertyStr(ctx, jq_obj, "serializeArray", JS_NewCFunction(ctx, js_serializeArray, "serializeArray", 0));
        JS_SetPropertyStr(ctx, jq_obj, "submit", JS_NewCFunction(ctx, js_submit, "submit", 1));

        // AJAX 메서드
        JS_SetPropertyStr(ctx, jq_obj, "load", JS_NewCFunction(ctx, js_load, "load", 1));

        // 이벤트 메서드
        JS_SetPropertyStr(ctx, jq_obj, "on", JS_NewCFunction(ctx, js_on, "on", 2));
        JS_SetPropertyStr(ctx, jq_obj, "off", JS_NewCFunction(ctx, js_off, "off", 2));
        JS_SetPropertyStr(ctx, jq_obj, "trigger", JS_NewCFunction(ctx, js_trigger, "trigger", 1));
        JS_SetPropertyStr(ctx, jq_obj, "click", JS_NewCFunction(ctx, js_click, "click", 1));
        JS_SetPropertyStr(ctx, jq_obj, "change", JS_NewCFunction(ctx, js_change, "change", 1));
        JS_SetPropertyStr(ctx, jq_obj, "focus", JS_NewCFunction(ctx, js_focus, "focus", 1));
        JS_SetPropertyStr(ctx, jq_obj, "blur", JS_NewCFunction(ctx, js_blur, "blur", 1));
        JS_SetPropertyStr(ctx, jq_obj, "keypress", JS_NewCFunction(ctx, js_keypress, "keypress", 1));
        JS_SetPropertyStr(ctx, jq_obj, "keydown", JS_NewCFunction(ctx, js_keydown, "keydown", 1));
        JS_SetPropertyStr(ctx, jq_obj, "keyup", JS_NewCFunction(ctx, js_keyup, "keyup", 1));
        JS_SetPropertyStr(ctx, jq_obj, "mouseenter", JS_NewCFunction(ctx, js_mouseenter, "mouseenter", 1));
        JS_SetPropertyStr(ctx, jq_obj, "mouseleave", JS_NewCFunction(ctx, js_mouseleave, "mouseleave", 1));
        JS_SetPropertyStr(ctx, jq_obj, "ready", JS_NewCFunction(ctx, js_ready, "ready", 1));
        JS_SetPropertyStr(ctx, jq_obj, "one", JS_NewCFunction(ctx, js_one, "one", 2));
        JS_SetPropertyStr(ctx, jq_obj, "hover", JS_NewCFunction(ctx, js_hover, "hover", 2));
        JS_SetPropertyStr(ctx, jq_obj, "dblclick", JS_NewCFunction(ctx, js_dblclick, "dblclick", 1));
        JS_SetPropertyStr(ctx, jq_obj, "scroll", JS_NewCFunction(ctx, js_scroll, "scroll", 1));
        JS_SetPropertyStr(ctx, jq_obj, "resize", JS_NewCFunction(ctx, js_resize, "resize", 1));
        JS_SetPropertyStr(ctx, jq_obj, "unload", JS_NewCFunction(ctx, js_unload, "unload", 1));
        JS_SetPropertyStr(ctx, jq_obj, "error", JS_NewCFunction(ctx, js_error, "error", 1));

        // 유틸리티 메서드
        JS_SetPropertyStr(ctx, jq_obj, "map", JS_NewCFunction(ctx, js_map, "map", 1));
        JS_SetPropertyStr(ctx, jq_obj, "is", JS_NewCFunction(ctx, js_is, "is", 1));
        JS_SetPropertyStr(ctx, jq_obj, "not", JS_NewCFunction(ctx, js_not, "not", 1));
        JS_SetPropertyStr(ctx, jq_obj, "has", JS_NewCFunction(ctx, js_has, "has", 1));

        // 치수/위치 메서드
        JS_SetPropertyStr(ctx, jq_obj, "width", JS_NewCFunction(ctx, js_width, "width", 1));
        JS_SetPropertyStr(ctx, jq_obj, "height", JS_NewCFunction(ctx, js_height, "height", 1));
        JS_SetPropertyStr(ctx, jq_obj, "offset", JS_NewCFunction(ctx, js_offset, "offset", 0));
        JS_SetPropertyStr(ctx, jq_obj, "position", JS_NewCFunction(ctx, js_position, "position", 0));
        JS_SetPropertyStr(ctx, jq_obj, "scrollTop", JS_NewCFunction(ctx, js_scrollTop, "scrollTop", 1));
        JS_SetPropertyStr(ctx, jq_obj, "scrollLeft", JS_NewCFunction(ctx, js_scrollLeft, "scrollLeft", 1));

        // 배열/컬렉션 메서드
        JS_SetPropertyStr(ctx, jq_obj, "get", JS_NewCFunction(ctx, js_getElement, "get", 1));
        JS_SetPropertyStr(ctx, jq_obj, "toArray", JS_NewCFunction(ctx, js_toArray, "toArray", 0));
        JS_SetPropertyStr(ctx, jq_obj, "index", JS_NewCFunction(ctx, js_index, "index", 0));
        JS_SetPropertyStr(ctx, jq_obj, "size", JS_NewCFunction(ctx, js_size, "size", 0));
        JS_SetPropertyStr(ctx, jq_obj, "slice", JS_NewCFunction(ctx, js_slice, "slice", 2));
        JS_SetPropertyStr(ctx, jq_obj, "add", JS_NewCFunction(ctx, js_add, "add", 1));
        JS_SetPropertyStr(ctx, jq_obj, "length", JS_NewInt32(ctx, 1));

        // Promise 메서드
        JS_SetPropertyStr(ctx, jq_obj, "promise", JS_NewCFunction(ctx, js_promise, "promise", 0));
        JS_SetPropertyStr(ctx, jq_obj, "then", JS_NewCFunction(ctx, js_then, "then", 2));
        JS_SetPropertyStr(ctx, jq_obj, "done", JS_NewCFunction(ctx, js_done, "done", 1));
        JS_SetPropertyStr(ctx, jq_obj, "fail", JS_NewCFunction(ctx, js_fail, "fail", 1));
        JS_SetPropertyStr(ctx, jq_obj, "always", JS_NewCFunction(ctx, js_always, "always", 1));

        return jq_obj;
    }

    void registerJQueryObject(JSContext* ctx, JSValue global_obj) {
        // $ 함수: 선택자를 받아 jQuery 객체 반환
        JSValue dollar_func = JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
            if (argc < 1) {
                return createJQueryObject(ctx, "");
            }

            // 함수가 전달되면 ready 핸들러로 처리
            if (JS_IsFunction(ctx, argv[0])) {
                JSValue ready_result = js_ready(ctx, this_val, argc, argv);
                // js_ready가 JS_UNDEFINED를 반환하므로 해제 불필요
                (void)ready_result;
                return createJQueryObject(ctx, "document");
            }

            std::string selector = JSValueConverter::toString(ctx, argv[0]);
            return createJQueryObject(ctx, selector.c_str());
        }, "$", 1);

        // $.ajax 계열
        JS_SetPropertyStr(ctx, dollar_func, "ajax", JS_NewCFunction(ctx, js_ajax, "ajax", 1));
        JS_SetPropertyStr(ctx, dollar_func, "get", JS_NewCFunction(ctx, js_get, "get", 1));
        JS_SetPropertyStr(ctx, dollar_func, "post", JS_NewCFunction(ctx, js_post, "post", 2));
        JS_SetPropertyStr(ctx, dollar_func, "getJSON", JS_NewCFunction(ctx, js_getJSON, "getJSON", 1));
        JS_SetPropertyStr(ctx, dollar_func, "getScript", JS_NewCFunction(ctx, js_getScript, "getScript", 1));

        // $.유틸리티
        JS_SetPropertyStr(ctx, dollar_func, "each", JS_NewCFunction(ctx, js_each, "each", 2));
        JS_SetPropertyStr(ctx, dollar_func, "extend", JS_NewCFunction(ctx, js_extend, "extend", 2));
        JS_SetPropertyStr(ctx, dollar_func, "parseJSON", JS_NewCFunction(ctx, js_parseJSON, "parseJSON", 1));
        JS_SetPropertyStr(ctx, dollar_func, "trim", JS_NewCFunction(ctx, js_trim, "trim", 1));
        JS_SetPropertyStr(ctx, dollar_func, "type", JS_NewCFunction(ctx, js_type, "type", 1));
        JS_SetPropertyStr(ctx, dollar_func, "isArray", JS_NewCFunction(ctx, js_isArray, "isArray", 1));
        JS_SetPropertyStr(ctx, dollar_func, "isFunction", JS_NewCFunction(ctx, js_isFunction, "isFunction", 1));
        JS_SetPropertyStr(ctx, dollar_func, "isNumeric", JS_NewCFunction(ctx, js_isNumeric, "isNumeric", 1));
        JS_SetPropertyStr(ctx, dollar_func, "isEmptyObject", JS_NewCFunction(ctx, js_isEmptyObject, "isEmptyObject", 1));
        JS_SetPropertyStr(ctx, dollar_func, "isPlainObject", JS_NewCFunction(ctx, js_isPlainObject, "isPlainObject", 1));
        JS_SetPropertyStr(ctx, dollar_func, "inArray", JS_NewCFunction(ctx, js_inArray, "inArray", 2));
        JS_SetPropertyStr(ctx, dollar_func, "grep", JS_NewCFunction(ctx, js_grep, "grep", 2));
        JS_SetPropertyStr(ctx, dollar_func, "merge", JS_NewCFunction(ctx, js_merge, "merge", 2));
        JS_SetPropertyStr(ctx, dollar_func, "makeArray", JS_NewCFunction(ctx, js_makeArray, "makeArray", 1));
        JS_SetPropertyStr(ctx, dollar_func, "unique", JS_NewCFunction(ctx, js_unique, "unique", 1));
        JS_SetPropertyStr(ctx, dollar_func, "globalEval", JS_NewCFunction(ctx, js_globalEval, "globalEval", 1));
        JS_SetPropertyStr(ctx, dollar_func, "noop", JS_NewCFunction(ctx, js_noop, "noop", 0));
        JS_SetPropertyStr(ctx, dollar_func, "now", JS_NewCFunction(ctx, js_now, "now", 0));

        // $.Deferred/Promise
        JS_SetPropertyStr(ctx, dollar_func, "Deferred", JS_NewCFunction(ctx, js_Deferred, "Deferred", 0));
        JS_SetPropertyStr(ctx, dollar_func, "when", JS_NewCFunction(ctx, js_when, "when", 1));

        // $.fn.valid (기존 코드 호환)
        JSValue fn_obj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, fn_obj, "valid", JS_NewCFunction(ctx, [](JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
            return JS_NewBool(ctx, 1);
        }, "valid", 0));
        JS_SetPropertyStr(ctx, dollar_func, "fn", fn_obj);

        // 전역에 $ 등록
        JS_SetPropertyStr(ctx, global_obj, "$", dollar_func);

        // jQuery alias
        JS_SetPropertyStr(ctx, global_obj, "jQuery", JS_DupValue(ctx, dollar_func));
    }
}
