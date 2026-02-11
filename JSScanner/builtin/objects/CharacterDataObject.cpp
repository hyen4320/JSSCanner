#include "pch.h"
#include "CharacterDataObject.h"
#include "../helpers/JSValueConverter.h"
#include "../helpers/MockHelpers.h"
#include "../../core/JSAnalyzer.h"

namespace CharacterDataObject {
    static JSAnalyzerContext* get_analyzer_context(JSContext* ctx) {
        return static_cast<JSAnalyzerContext*>(JS_GetContextOpaque(ctx));
    }

    /**
     * substringData(offset, count) - 문자 데이터의 부분 문자열을 반환
     */
    JSValue js_characterData_substringData(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 2) {
            return JS_UNDEFINED;
        }

        // 현재 data 속성 가져오기
        JSValue data_val = JS_GetPropertyStr(ctx, this_val, "data");
        std::string data = JSValueConverter::toString(ctx, data_val);
        JS_FreeValue(ctx, data_val);

        // offset과 count 파라미터 가져오기
        int32_t offset = 0;
        int32_t count = 0;
        JS_ToInt32(ctx, &offset, argv[0]);
        JS_ToInt32(ctx, &count, argv[1]);

        // 범위 검증
        if (offset < 0 || offset > static_cast<int32_t>(data.length())) {
            return JS_ThrowRangeError(ctx, "Index or size is negative or greater than the allowed amount");
        }

        // 부분 문자열 추출
        size_t start = static_cast<size_t>(offset);
        size_t length = std::min(static_cast<size_t>(count), data.length() - start);
        std::string result = data.substr(start, length);

        return JS_NewString(ctx, result.c_str());
    }

    /**
     * appendData(data) - 문자 데이터 끝에 문자열 추가
     */
    JSValue js_characterData_appendData(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) {
            return JS_UNDEFINED;
        }

        // 추가할 데이터
        std::string newData = JSValueConverter::toString(ctx, argv[0]);

        // 현재 data 속성 가져오기
        JSValue data_val = JS_GetPropertyStr(ctx, this_val, "data");
        std::string currentData = JSValueConverter::toString(ctx, data_val);
        JS_FreeValue(ctx, data_val);

        // 데이터 추가
        currentData += newData;

        // data 속성 업데이트
        JSValue thisDup = JS_DupValue(ctx, this_val);
        JS_SetPropertyStr(ctx, thisDup, "data", JS_NewString(ctx, currentData.c_str()));
        JS_FreeValue(ctx, thisDup);

        return JS_UNDEFINED;
    }

    /**
     * insertData(offset, data) - 지정된 오프셋에 문자열 삽입
     */
    JSValue js_characterData_insertData(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 2) {
            return JS_UNDEFINED;
        }

        // offset과 삽입할 데이터 가져오기
        int32_t offset = 0;
        JS_ToInt32(ctx, &offset, argv[0]);
        std::string insertStr = JSValueConverter::toString(ctx, argv[1]);

        // 현재 data 속성 가져오기
        JSValue data_val = JS_GetPropertyStr(ctx, this_val, "data");
        std::string currentData = JSValueConverter::toString(ctx, data_val);
        JS_FreeValue(ctx, data_val);

        // 범위 검증
        if (offset < 0 || offset > static_cast<int32_t>(currentData.length())) {
            return JS_ThrowRangeError(ctx, "Index or size is negative or greater than the allowed amount");
        }

        // 데이터 삽입
        size_t pos = static_cast<size_t>(offset);
        currentData.insert(pos, insertStr);

        // data 속성 업데이트
        JSValue thisDup = JS_DupValue(ctx, this_val);
        JS_SetPropertyStr(ctx, thisDup, "data", JS_NewString(ctx, currentData.c_str()));
        JS_FreeValue(ctx, thisDup);

        return JS_UNDEFINED;
    }

    /**
     * deleteData(offset, count) - 지정된 오프셋에서 문자 삭제
     */
    JSValue js_characterData_deleteData(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 2) {
            return JS_UNDEFINED;
        }

        // offset과 count 파라미터 가져오기
        int32_t offset = 0;
        int32_t count = 0;
        JS_ToInt32(ctx, &offset, argv[0]);
        JS_ToInt32(ctx, &count, argv[1]);

        // 현재 data 속성 가져오기
        JSValue data_val = JS_GetPropertyStr(ctx, this_val, "data");
        std::string currentData = JSValueConverter::toString(ctx, data_val);
        JS_FreeValue(ctx, data_val);

        // 범위 검증
        if (offset < 0 || offset > static_cast<int32_t>(currentData.length())) {
            return JS_ThrowRangeError(ctx, "Index or size is negative or greater than the allowed amount");
        }

        // 데이터 삭제
        size_t start = static_cast<size_t>(offset);
        size_t length = std::min(static_cast<size_t>(count), currentData.length() - start);
        currentData.erase(start, length);

        // data 속성 업데이트
        JSValue thisDup = JS_DupValue(ctx, this_val);
        JS_SetPropertyStr(ctx, thisDup, "data", JS_NewString(ctx, currentData.c_str()));
        JS_FreeValue(ctx, thisDup);

        return JS_UNDEFINED;
    }

    /**
     * replaceData(offset, count, data) - 지정된 오프셋에서 문자를 교체
     */
    JSValue js_characterData_replaceData(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 3) {
            return JS_UNDEFINED;
        }

        // offset, count, 교체할 데이터 가져오기
        int32_t offset = 0;
        int32_t count = 0;
        JS_ToInt32(ctx, &offset, argv[0]);
        JS_ToInt32(ctx, &count, argv[1]);
        std::string replaceStr = JSValueConverter::toString(ctx, argv[2]);

        // 현재 data 속성 가져오기
        JSValue data_val = JS_GetPropertyStr(ctx, this_val, "data");
        std::string currentData = JSValueConverter::toString(ctx, data_val);
        JS_FreeValue(ctx, data_val);

        // 범위 검증
        if (offset < 0 || offset > static_cast<int32_t>(currentData.length())) {
            return JS_ThrowRangeError(ctx, "Index or size is negative or greater than the allowed amount");
        }

        // 데이터 교체 (삭제 후 삽입)
        size_t start = static_cast<size_t>(offset);
        size_t length = std::min(static_cast<size_t>(count), currentData.length() - start);
        currentData.erase(start, length);
        currentData.insert(start, replaceStr);

        // data 속성 업데이트
        JSValue thisDup = JS_DupValue(ctx, this_val);
        JS_SetPropertyStr(ctx, thisDup, "data", JS_NewString(ctx, currentData.c_str()));
        JS_FreeValue(ctx, thisDup);

        // 분석 컨텍스트에 기록 (필요시)
        JSAnalyzerContext* a_ctx = get_analyzer_context(ctx);
        if (a_ctx && a_ctx->dynamicAnalyzer) {
            a_ctx->dynamicAnalyzer->recordEvent({
                HookType::DOM_MANIPULATION, 
                "replaceData",
                {JsValue(offset), JsValue(count), JsValue(replaceStr)},
                JsValue(std::monostate()),
                {},
                3
            });
        }

        return JS_UNDEFINED;
    }
}
