#pragma once
#include "../../quickjs.h"
#include <string>
#include <set>

/**
 * Mock 객체 생성 및 헬퍼 함수들
 */
namespace MockHelpers {
    /**
     * Mock Element 생성
     * @param ctx JavaScript 컨텍스트
     * @param id Element ID
     * @return Mock Element 객체
     */
    JSValue createMockElement(JSContext* ctx, const std::string& id);

    /**
     * Mock Event 객체 생성
     * @param ctx JavaScript 컨텍스트
     * @param currentTarget 이벤트 대상
     * @param eventName 이벤트 이름
     * @param targetOverride 타겟 오버라이드
     * @return Mock Event 객체
     */
    JSValue createEventObject(JSContext* ctx, JSValueConst currentTarget, 
                             const std::string& eventName, JSValue targetOverride = JS_UNDEFINED);

    /**
     * ClassList 객체 생성
     * @param ctx JavaScript 컨텍스트
     * @return ClassList 객체
     */
    JSValue createClassListObject(JSContext* ctx);

    /**
     * Style 객체 생성
     * @param ctx JavaScript 컨텍스트
     * @return Style 객체
     */
    JSValue createStyleObject(JSContext* ctx);

    /**
     * Element에 문자열 프로퍼티 설정
     * @param ctx JavaScript 컨텍스트
     * @param element Element 객체
     * @param name 프로퍼티 이름
     * @param value 프로퍼티 값
     */
    void setElementStringProperty(JSContext* ctx, JSValue element, const char* name, const std::string& value);

    /**
     * Mock Attribute 설정
     * @param ctx JavaScript 컨텍스트
     * @param element Element 객체
     * @param name Attribute 이름
     * @param value Attribute 값
     */
    void setMockAttribute(JSContext* ctx, JSValue element, const std::string& name, const std::string& value);

    /**
     * Element의 기본 값 가져오기
     * @param id Element ID
     * @return 기본 값
     */
    std::string getDefaultElementValue(const std::string& id);

    /**
     * Element의 기본 텍스트 가져오기
     * @param id Element ID
     * @return 기본 텍스트
     */
    std::string getDefaultElementText(const std::string& id);

    /**
     * Class 토큰 파싱
     * @param tokenStr 토큰 문자열
     * @return 토큰 세트
     */
    std::set<std::string> parseClassTokens(const std::string& tokenStr);

    /**
     * Class 토큰 합치기
     * @param tokens 토큰 세트
     * @return 합쳐진 문자열
     */
    std::string joinClassTokens(const std::set<std::string>& tokens);

    /**
     * ClassList에 토큰 추가
     * @param ctx JavaScript 컨텍스트
     * @param classList ClassList 객체
     * @param token 추가할 토큰
     */
    void classListAddToken(JSContext* ctx, JSValue classList, const std::string& token);
}
