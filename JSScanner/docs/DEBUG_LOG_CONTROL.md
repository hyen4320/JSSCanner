# Debug 로그 출력 제어 구현

## 📋 개요
모든 디버그 로그([HOOK], [CHAIN], [TAINT], [WARNING])가 `--debug` 옵션을 줄 때만 출력되도록 수정했습니다.

## ✅ 수정된 파일 (5개)

### 1. utils/Logger.cpp
**변경 내용**: `Logger::hook()` 함수가 debug 모드일 때만 작동하도록 수정

```cpp
void Logger::hook(const std::string& message, int severity) {
    // Hook 로그는 debug 모드일 때만 출력
    if (!debugEnabled_.load(std::memory_order_relaxed)) {
        return;
    }
    if (!hookLoggingEnabled_.load(std::memory_order_relaxed)) {
        return;
    }
    logHook(message, severity);
}
```

### 2. main.cpp
**변경 내용**: DLL의 `Scan()` 함수에서도 Hook 로그를 비활성화

```cpp
SCANNER_EXPORT void Scan(const char* url, int task_id)
{
    try
    {
        Logger::setDebugEnabled(false);
        Logger::setHookLoggingEnabled(false);  // 변경: false로 설정
        // ...
    }
}
```

### 3. core/TaintTracker.cpp
**변경 내용**: 하드코딩된 `SCANNER_DEBUG_MODE` 제거하고 Logger 사용

**변경 전:**
```cpp
#ifndef SCANNER_DEBUG_MODE
#define SCANNER_DEBUG_MODE true // 항상 true
#endif

static void debug_taint(const std::string& message) {
    if (SCANNER_DEBUG_MODE) {
        std::cout << "[TAINT] " << message << std::endl;
    }
}
```

**변경 후:**
```cpp
#include "../utils/Logger.h"

static void debug_taint(const std::string& message) {
    Logger::debug("[TAINT] " + message);
}
```

### 4. chain/ChainDetector.cpp
**변경 내용**: 하드코딩된 `SCANNER_DEBUG_MODE` 제거하고 Logger 사용

**변경 전:**
```cpp
#ifndef SCANNER_DEBUG_MODE
#define SCANNER_DEBUG_MODE true // 항상 true
#endif

static void debug_chain(const std::string& message) {
    if (SCANNER_DEBUG_MODE) {
        std::cout << "[CHAIN] " << message << std::endl;
    }
}
```

**변경 후:**
```cpp
#include "../utils/Logger.h"

static void debug_chain(const std::string& message) {
    Logger::debug("[CHAIN] " + message);
}
```

### 5. builtin/objects/StringObject.cpp
**변경 내용**: `std::cout` WARNING을 `Logger::warn()`으로 변경

**변경 전:**
```cpp
std::cout << "[WARNING] String.fromCharCode exceeded " << JSAnalyzerContext::MAX_FUNCTION_CALLS
          << " calls - further calls will be ignored to prevent DoS" << std::endl;
```

**변경 후:**
```cpp
Logger::warn("String.fromCharCode exceeded " + std::to_string(JSAnalyzerContext::MAX_FUNCTION_CALLS) +
             " calls - further calls will be ignored to prevent DoS");
```

### 6. builtin/objects/GlobalObject.cpp
**변경 내용**: `std::cout` WARNING을 `Logger::warn()`으로 변경

**변경 전:**
```cpp
std::cout << "[WARNING] atob exceeded " << JSAnalyzerContext::MAX_FUNCTION_CALLS
          << " calls - further calls will be ignored to prevent DoS" << std::endl;
```

**변경 후:**
```cpp
Logger::warn("atob exceeded " + std::to_string(JSAnalyzerContext::MAX_FUNCTION_CALLS) +
             " calls - further calls will be ignored to prevent DoS");
```

## 🎯 사용 방법

### 일반 모드 (로그 출력 안 됨)
```bash
./JSScanner test.js
./JSScanner test.html task-123
```

**출력 예시:**
```
[2025-11-08 15:31:32.000] INFO: HtmlJSScanner (C++) starting
[2025-11-08 15:31:32.001] INFO: Input path: test.js
[2025-11-08 15:31:32.002] INFO: TaskId: task-123
[2025-11-08 15:31:32.100] INFO: Analysis finished in 100 ms
```

### Debug 모드 (모든 로그 출력)
```bash
./JSScanner test.js task-123 --debug
```

**출력 예시:**
```
[2025-11-08 15:31:32.000] INFO: HtmlJSScanner (C++) starting
[2025-11-08 15:31:32.001] INFO: Input path: test.js
[2025-11-08 15:31:32.002] INFO: TaskId: task-123
[2025-11-08 15:31:32.003] DEBUG: Debug logging enabled
[2025-11-08 15:31:32.100] HOOK(sev=10): FUNCTION_CALL - eval("malicious code")
[2025-11-08 15:31:32.101] DEBUG: [CHAIN] Detecting: eval
[2025-11-08 15:31:32.102] DEBUG: [TAINT] Created: TaintedValue(taint_1, val="test", src=eval, level=8)
[2025-11-08 15:31:32.103] HOOK(sev=7): FETCH_REQUEST - fetch(https://evil.com)
[2025-11-08 15:31:32.200] WARN: atob exceeded 1000 calls - further calls will be ignored to prevent DoS
[2025-11-08 15:31:32.300] INFO: Analysis finished in 300 ms
```

## 📊 제어되는 로그 종류

| 로그 타입 | 설명 | 일반 모드 | Debug 모드 |
|---------|------|---------|-----------|
| `[HOOK]` | 함수 호출 이벤트 | ❌ | ✅ |
| `[CHAIN]` | 공격 체인 탐지 | ❌ | ✅ |
| `[TAINT]` | Taint 추적 정보 | ❌ | ✅ |
| `[WARNING]` | 제한 초과 경고 | ✅ | ✅ |
| `[INFO]` | 일반 정보 | ✅ | ✅ |
| `[ERROR]` | 에러 메시지 | ✅ | ✅ |
| `[DEBUG]` | 디버그 메시지 | ❌ | ✅ |

## 🔄 통합 로직

모든 디버그 로그가 `Logger` 클래스를 통해 중앙 집중식으로 관리됩니다:

```
Logger::setDebugEnabled(false)  →  모든 debug 로그 비활성화
Logger::setDebugEnabled(true)   →  모든 debug 로그 활성화
```

## ✨ 장점

1. **깔끔한 출력**: 일반 실행 시 중요한 정보만 표시
2. **중앙 관리**: 모든 로그가 Logger를 통해 제어됨
3. **일관성**: 모든 디버그 로그가 동일한 플래그로 제어됨
4. **성능**: 불필요한 로그 출력으로 인한 성능 저하 방지
5. **디버깅 용이**: `--debug` 옵션으로 상세 정보 확인 가능

## 🔧 재빌드 필요

이 변경사항들은 C++ 소스 코드 수정이므로 **반드시 재빌드**가 필요합니다:

```bash
# Visual Studio
빌드 → 솔루션 다시 빌드

# CMake
cd build
cmake --build . --config Release
```

## 📝 작성일
2025-11-08
