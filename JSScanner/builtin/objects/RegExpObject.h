#pragma once
#include "quickjs.h"

/**
 * RegExpObject - 정규 표현식 객체
 * 
 * JavaScript의 RegExp 객체를 QuickJS 환경에 제공합니다.
 * 주요 메서드:
 * - RegExp.prototype.test(string) - 문자열이 패턴과 일치하는지 테스트
 * - RegExp.prototype.exec(string) - 패턴 매칭 결과 반환
 * - String.prototype.match(regexp) - 문자열에서 패턴 매칭
 * - String.prototype.replace(regexp, replacement) - 패턴 기반 문자열 치환
 */

namespace RegExpObject {

/**
 * RegExp.prototype.test(string)
 * 정규식이 문자열과 매치되는지 boolean 반환
 */
JSValue js_regexp_test(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);

/**
 * RegExp.prototype.exec(string)
 * 정규식 매칭 결과를 배열로 반환 (매치되지 않으면 null)
 */
JSValue js_regexp_exec(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);

/**
 * String.prototype.match(regexp)
 * 문자열에서 정규식과 매칭되는 부분 찾기
 */
JSValue js_string_match(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);

/**
 * String.prototype.replace(regexp, replacement)
 * 정규식으로 문자열 치환
 */
JSValue js_string_replace(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);

/**
 * RegExp 객체 등록
 */
void registerRegExpMethods(JSContext* ctx, JSValue global_obj);

} // namespace RegExpObject
