#pragma once
#include "../quickjs.h"
#include <stdexcept>
#include <chrono>
#include <atomic>

// 🔥 Task별 독립적인 JSRuntime/JSContext 관리 (RAII 패턴)
// 멀티스레드 환경에서 안전하게 QuickJS를 사용하기 위한 클래스
class ScopedJSRuntime {
private:
    JSRuntime* runtime_;
    JSContext* context_;
    bool initialized_;
    bool corrupted_;
    
    // 타임아웃 관리
    std::chrono::steady_clock::time_point start_time_;
    std::chrono::milliseconds timeout_;
    std::atomic<bool> should_interrupt_;
    
    // 인터럽트 핸들러
    static int InterruptHandler(JSRuntime* rt, void* opaque) {
        auto* self = static_cast<ScopedJSRuntime*>(opaque);
        
        if (self->should_interrupt_.load()) {
            return 1; // 중단 요청
        }
        
        auto elapsed = std::chrono::steady_clock::now() - self->start_time_;
        if (elapsed > self->timeout_) {
            return 1; // 타임아웃
        }
        
        return 0; // 계속 실행
    }

public:
    // 생성자: 독립적인 JSRuntime과 JSContext 생성
    explicit ScopedJSRuntime(std::chrono::milliseconds timeout = std::chrono::milliseconds(30000))
        : runtime_(nullptr)
        , context_(nullptr)
        , initialized_(false)
        , corrupted_(false)
        , timeout_(timeout)
        , should_interrupt_(false)
    {
        start_time_ = std::chrono::steady_clock::now();
        
        // JSRuntime 생성
        runtime_ = JS_NewRuntime();
        if (!runtime_) {
            throw std::runtime_error("Failed to create JSRuntime");
        }
        
        // 런타임 설정
        JS_SetMemoryLimit(runtime_, 256 * 1024 * 1024);  // 256MB
        JS_SetMaxStackSize(runtime_, 8 * 1024 * 1024);   // 8MB
        JS_SetGCThreshold(runtime_, 2 * 1024 * 1024);    // 2MB GC 임계값
        
        // 인터럽트 핸들러 설정
        JS_SetInterruptHandler(runtime_, InterruptHandler, this);
        
        // JSContext 생성
        context_ = JS_NewContext(runtime_);
        if (!context_) {
            JS_FreeRuntime(runtime_);
            runtime_ = nullptr;
            throw std::runtime_error("Failed to create JSContext");
        }
        
        initialized_ = true;
    }
    
    // 소멸자: 자동으로 정리
    ~ScopedJSRuntime() {
        // 🔥 CRITICAL WORKAROUND: QuickJS GC crashes in multithreaded environment
        // Always skip cleanup to prevent segfault
        // This causes memory leak but prevents crashes
        // TODO: Replace QuickJS with a stable JS engine or use separate process
        
        // ⚠️ Memory leak workaround - but stability is more important
        if (context_) {
            // Try to free context (safer than runtime)
            try {
                JS_FreeContext(context_);
            } catch (...) {
                // Ignore any exception
            }
            context_ = nullptr;
        }
        
        // ⚠️ NEVER call JS_FreeRuntime - it causes GC crash
        // Just leak the runtime memory (small compared to preventing crashes)
        runtime_ = nullptr;
    }
    
    // 복사/이동 금지 (안전성)
    ScopedJSRuntime(const ScopedJSRuntime&) = delete;
    ScopedJSRuntime& operator=(const ScopedJSRuntime&) = delete;
    ScopedJSRuntime(ScopedJSRuntime&&) = delete;
    ScopedJSRuntime& operator=(ScopedJSRuntime&&) = delete;
    
    // Getter
    JSContext* GetContext() const { return context_; }
    JSRuntime* GetRuntime() const { return runtime_; }
    bool IsInitialized() const { return initialized_; }
    bool IsCorrupted() const { return corrupted_; }
    
    // 런타임 손상 표시 (에러 발생 시 호출)
    void MarkCorrupted() { corrupted_ = true; }
    
    // 실행 중단 요청
    void RequestInterrupt() {
        should_interrupt_.store(true);
    }
    
    // 타임아웃 시간 재설정
    void ResetTimeout() {
        start_time_ = std::chrono::steady_clock::now();
        should_interrupt_.store(false);
    }
};
