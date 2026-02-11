#pragma once
#include "../../quickjs.h"

/**
 * CharacterData 객체의 메서드들
 * Text, Comment 노드의 부모 인터페이스
 */
namespace CharacterDataObject {
    /**
     * CharacterData 메서드들
     */
    JSValue js_characterData_substringData(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_characterData_appendData(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_characterData_insertData(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_characterData_deleteData(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
    JSValue js_characterData_replaceData(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
}
