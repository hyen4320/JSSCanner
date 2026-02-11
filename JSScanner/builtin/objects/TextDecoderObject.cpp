#include "pch.h"
#include "TextDecoderObject.h"
#include <string>
#include <vector>
#include <cstring>

// Windows에서 strcasecmp 사용을 위한 매크로
#ifdef _WIN32
#define strcasecmp _stricmp
#endif

// ================================
// TextDecoder 객체 구현
// ================================
namespace TextDecoderObject {

    /**
     * TextDecoder.prototype.encoding getter
     * 항상 "utf-8" 문자열을 반환
     */
    JSValue js_textdecoder_encoding_get(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        return JS_NewString(ctx, "utf-8");
    }

    /**
     * TextDecoder.prototype.decode
     * Uint8Array 또는 ArrayBuffer를 문자열로 디코딩
     */
    JSValue js_textdecoder_decode(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
        if (argc < 1) {
            return JS_ThrowTypeError(ctx, "decode() requires one argument");
        }

        size_t len = 0;
        uint8_t* data = nullptr;

        // 인자가 ArrayBuffer인지 확인
        if (JS_IsArrayBuffer(argv[0])) {
            data = static_cast<uint8_t*>(JS_GetArrayBuffer(ctx, &len, argv[0]));
        }
        // 아니면 TypedArray(Uint8Array 등)인지 확인
        else if (JS_IsObject(argv[0])) {
            size_t byte_offset = 0;
            size_t byte_length = 0;
            size_t bytes_per_element = 0;
            JSValue buffer = JS_GetTypedArrayBuffer(ctx, argv[0], &byte_offset, &byte_length, &bytes_per_element);
            if (!JS_IsException(buffer)) {
                size_t buffer_size = 0;
                data = static_cast<uint8_t*>(JS_GetArrayBuffer(ctx, &buffer_size, buffer));
                if (data) {
                    data += byte_offset;
                    len = byte_length;
                }
                JS_FreeValue(ctx, buffer);
            }
        }

        if (!data || len == 0) {
            return JS_ThrowTypeError(ctx, "Invalid ArrayBuffer or TypedArray");
        }

        // 🔍 UTF-8 유효성 검증 (기본적인 검사)
        // 유효하지 않은 바이트 시퀀스가 있으면 replacement character (U+FFFD)로 대체
        std::string decoded;
        decoded.reserve(len);
        
        for (size_t i = 0; i < len; ) {
            uint8_t byte = data[i];
            
            // ASCII (0x00-0x7F)
            if (byte <= 0x7F) {
                decoded.push_back(static_cast<char>(byte));
                i++;
            }
            // 2바이트 UTF-8 (0xC0-0xDF)
            else if ((byte >= 0xC0) && (byte <= 0xDF) && (i + 1 < len)) {
                uint8_t byte2 = data[i + 1];
                if ((byte2 & 0xC0) == 0x80) {  // 유효한 continuation byte
                    decoded.push_back(static_cast<char>(byte));
                    decoded.push_back(static_cast<char>(byte2));
                    i += 2;
                } else {
                    // 유효하지 않은 시퀀스 - replacement character (간단히 ?로 대체)
                    decoded.push_back('?');
                    i++;
                }
            }
            // 3바이트 UTF-8 (0xE0-0xEF)
            else if ((byte >= 0xE0) && (byte <= 0xEF) && (i + 2 < len)) {
                uint8_t byte2 = data[i + 1];
                uint8_t byte3 = data[i + 2];
                if ((byte2 & 0xC0) == 0x80 && (byte3 & 0xC0) == 0x80) {
                    decoded.push_back(static_cast<char>(byte));
                    decoded.push_back(static_cast<char>(byte2));
                    decoded.push_back(static_cast<char>(byte3));
                    i += 3;
                } else {
                    decoded.push_back('?');
                    i++;
                }
            }
            // 4바이트 UTF-8 (0xF0-0xF7)
            else if ((byte >= 0xF0) && (byte <= 0xF7) && (i + 3 < len)) {
                uint8_t byte2 = data[i + 1];
                uint8_t byte3 = data[i + 2];
                uint8_t byte4 = data[i + 3];
                if ((byte2 & 0xC0) == 0x80 && (byte3 & 0xC0) == 0x80 && (byte4 & 0xC0) == 0x80) {
                    decoded.push_back(static_cast<char>(byte));
                    decoded.push_back(static_cast<char>(byte2));
                    decoded.push_back(static_cast<char>(byte3));
                    decoded.push_back(static_cast<char>(byte4));
                    i += 4;
                } else {
                    decoded.push_back('?');
                    i++;
                }
            }
            // 유효하지 않은 UTF-8 바이트
            else {
                decoded.push_back('?');
                i++;
            }
        }
        
        return JS_NewStringLen(ctx, decoded.c_str(), decoded.size());
    }

    /**
     * TextDecoder 생성자
     * 기본적으로 utf-8만 지원
     */
    JSValue js_textdecoder_constructor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv) {
        // 인코딩 이름이 주어졌다면 검사
        if (argc >= 1 && JS_IsString(argv[0])) {
            const char* encoding = JS_ToCString(ctx, argv[0]);
            if (encoding && strcasecmp(encoding, "utf-8") != 0) {
                JS_FreeCString(ctx, encoding);
                return JS_ThrowTypeError(ctx, "Only 'utf-8' encoding is supported");
            }
            JS_FreeCString(ctx, encoding);
        }

        // 인스턴스 객체 생성
        JSValue proto = JS_GetPropertyStr(ctx, new_target, "prototype");
        JSValue obj = JS_NewObjectProtoClass(ctx, proto, 0);
        JS_FreeValue(ctx, proto);
        return obj;
    }

    /**
     * TextDecoder 등록
     */
    void registerTextDecoder(JSContext* ctx, JSValue global_obj) {
        // 프로토타입 객체 생성
        JSValue proto = JS_NewObject(ctx);

        // decode 메서드 등록
        JS_SetPropertyStr(ctx, proto, "decode",
            JS_NewCFunction(ctx, js_textdecoder_decode, "decode", 1));

        // encoding getter 등록
        JSAtom encoding_atom = JS_NewAtom(ctx, "encoding");
        JS_DefinePropertyGetSet(
            ctx, proto,
            encoding_atom,
            JS_NewCFunction2(ctx, js_textdecoder_encoding_get, "encoding", 0, JS_CFUNC_generic, 0),
            JS_UNDEFINED,
            JS_PROP_CONFIGURABLE | JS_PROP_ENUMERABLE
        );
        JS_FreeAtom(ctx, encoding_atom);

        // 생성자 등록
        JSValue ctor = JS_NewCFunction2(
            ctx,
            js_textdecoder_constructor,
            "TextDecoder",
            1,
            JS_CFUNC_constructor,
            0
        );

        JS_SetConstructor(ctx, ctor, proto);
        JS_SetPropertyStr(ctx, global_obj, "TextDecoder", ctor);

        // 프로토타입 해제
        JS_FreeValue(ctx, proto);
    }

} // namespace TextDecoderObject
