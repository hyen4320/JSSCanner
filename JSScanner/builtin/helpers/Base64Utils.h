#pragma once
#include <string>

namespace Base64Utils {
    /**
     * Base64 디코딩 함수
     * @param encoded_string Base64로 인코딩된 문자열
     * @return 디코딩된 문자열
     */
    std::string decode(const std::string& encoded_string);
    
    /**
     * 문자가 Base64 문자인지 확인
     * @param c 확인할 문자
     * @return Base64 문자이면 true
     */
    bool isBase64Char(unsigned char c);
}
