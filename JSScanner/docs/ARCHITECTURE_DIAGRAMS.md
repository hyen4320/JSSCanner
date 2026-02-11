# HtmlJSScanner 아키텍처 다이어그램

## 1. 전체 시스템 아키텍처

```mermaid
graph TB
    subgraph "Entry Point"
        A[main.cpp / DLL Export]
    end
    
    subgraph "Core Analysis Engine"
        B[JSAnalyzer]
        C[QuickJS Runtime]
        D[DynamicAnalyzer]
        E[ChainTrackerManager]
    end
    
    subgraph "Advanced Analysis"
        F[ChainDetector]
        G[TaintTracker]
        H[DynamicStringTracker]
        I[StringDeobfuscator]
    end
    
    subgraph "Browser Environment"
        J[WindowObject]
        K[DocumentObject]
        L[XMLHTTPRequestObject]
        M[Other Builtin Objects]
    end
    
    subgraph "Output"
        N[ResponseGenerator]
        O[HtmlJsReportWriter]
        P[JSON Report]
    end
    
    A --> B
    B --> C
    B --> D
    B --> E
    
    C --> J
    C --> K
    C --> L
    C --> M
    
    E --> F
    F --> G
    D --> H
    H --> I
    
    B --> N
    N --> O
    O --> P
    
    style A fill:#e3f2fd
    style B fill:#fff3e0
    style F fill:#f3e5f5
    style N fill:#e8f5e9
    style P fill:#ffebee
```

## 2. 데이터 흐름 다이어그램

```mermaid
flowchart TD
    START([HTML/JS 입력]) --> PARSE[HTML 파싱<br/>TagParser]
    PARSE --> EXTRACT[JavaScript 추출]
    
    EXTRACT --> STATIC[정적 분석<br/>패턴 매칭]
    EXTRACT --> DYNAMIC[동적 분석<br/>QuickJS 실행]
    
    STATIC --> PATTERNS[민감 패턴<br/>키워드 탐지]
    STATIC --> URLS[URL 추출<br/>UrlCollector]
    
    DYNAMIC --> HOOKS[Hook 이벤트<br/>수집]
    HOOKS --> EVENTS[DynamicAnalyzer]
    
    EVENTS --> TAINT[Taint 추적<br/>TaintTracker]
    EVENTS --> CHAIN[공격 체인<br/>ChainDetector]
    EVENTS --> STRING[문자열 추적<br/>DynamicStringTracker]
    
    PATTERNS --> MERGE[결과 통합]
    URLS --> MERGE
    TAINT --> MERGE
    CHAIN --> MERGE
    STRING --> MERGE
    
    MERGE --> REPORT[보고서 생성<br/>ResponseGenerator]
    REPORT --> OUTPUT([JSON 파일 출력])
    
    style START fill:#4caf50
    style DYNAMIC fill:#ff9800
    style TAINT fill:#e91e63
    style CHAIN fill:#9c27b0
    style STRING fill:#2196f3
    style OUTPUT fill:#f44336
```

## 3. Hook 시스템 상호작용

```mermaid
sequenceDiagram
    participant JS as JavaScript Code
    participant QJS as QuickJS Engine
    participant Hook as Hooked Function
    participant DA as DynamicAnalyzer
    participant CD as ChainDetector
    participant TT as TaintTracker
    
    JS->>QJS: eval("malicious")
    QJS->>Hook: GlobalObject.eval()
    
    Note over Hook: 호출 전 처리
    Hook->>DA: recordEvent(HookEvent)
    Hook->>TT: createTaintedValue()
    Hook->>CD: detectFunctionCall()
    
    CD->>TT: findTaintByValue()
    TT-->>CD: TaintedValue
    CD->>CD: 체인 생성/확장
    
    Note over Hook: 실제 함수 실행
    Hook->>QJS: 원본 eval 실행
    QJS->>Hook: 결과 반환
    
    Note over Hook: 호출 후 처리
    Hook->>TT: propagateTaint()
    Hook->>JS: 결과 반환
```

## 4. Taint 전파 메커니즘

```mermaid
graph TD
    A[외부 입력<br/>window.location.search] -->|createTaintedValue| B[TaintedValue#1<br/>Level: 8]
    
    B -->|taintVariable| C[변수 userInput]
    C -->|문자열 연산| D[변수 processedData]
    D -->|propagateTaint| E[TaintedValue#2<br/>Level: 8]
    
    E -->|함수 전달| F[변수 payloadString]
    F -->|propagateTaint| G[TaintedValue#3<br/>Level: 8]
    
    G -->|eval 인자| H{위험 함수<br/>도달}
    H -->|Yes| I[🚨 Detection 생성<br/>Severity: 9]
    
    B -.->|propagationGraph| E
    E -.->|propagationGraph| G
    
    style A fill:#4caf50
    style B fill:#fff176
    style E fill:#fff176
    style G fill:#fff176
    style H fill:#ff5722
    style I fill:#f44336
```

## 5. 공격 체인 재구성 과정

```mermaid
stateDiagram-v2
    [*] --> WaitingForDecoder: 함수 호출 감지
    
    WaitingForDecoder --> ChainStarted: atob() 호출<br/>(디코더 함수)
    ChainStarted --> ChainExtended: eval() 호출<br/>(난독화 해제)
    ChainExtended --> ChainCompleted: fetch() 호출<br/>(위험 함수)
    
    ChainCompleted --> Verification: 인과관계 검증
    
    Verification --> Valid: 체인 유효
    Verification --> Invalid: 체인 무효
    
    Valid --> [*]: completedChains에 추가
    Invalid --> [*]: 폐기
    
    WaitingForDecoder --> WaitingForDecoder: 일반 함수<br/>(무시)
    ChainStarted --> ChainStarted: 일반 함수<br/>(체인 확장 안 함)
```

## 6. 컴포넌트 의존성 그래프

```mermaid
graph LR
    subgraph "main.cpp"
        Main[main 함수]
    end
    
    subgraph "core/"
        JSA[JSAnalyzer]
        DA[DynamicAnalyzer]
        TT[TaintTracker]
        TV[TaintedValue]
        DST[DynamicStringTracker]
        SD[StringDeobfuscator]
        CTM[ChainTrackerManager]
    end
    
    subgraph "chain/"
        CD[ChainDetector]
        AC[AttackChain]
        CS[ChainStep]
    end
    
    subgraph "builtin/"
        GO[GlobalObject]
        WO[WindowObject]
        DO[DocumentObject]
        XHR[XMLHTTPRequestObject]
    end
    
    subgraph "hooks/"
        HT[HookType]
        HE[HookEvent]
    end
    
    subgraph "reporters/"
        RG[ResponseGenerator]
        RW[HtmlJsReportWriter]
    end
    
    Main --> JSA
    
    JSA --> DA
    JSA --> CTM
    JSA --> DST
    JSA --> RG
    
    DA --> HE
    HE --> HT
    
    CTM --> CD
    CD --> TT
    CD --> AC
    AC --> CS
    
    TT --> TV
    
    DST --> SD
    
    GO --> DA
    WO --> DA
    DO --> DA
    XHR --> DA
    
    RG --> RW
    
    style Main fill:#e3f2fd
    style JSA fill:#fff3e0
    style CD fill:#f3e5f5
    style TT fill:#ffebee
    style RG fill:#e8f5e9
```

## 7. 클래스 다이어그램 (주요 클래스)

```mermaid
classDiagram
    class JSAnalyzer {
        -JSRuntime* rt
        -JSContext* ctx
        -DynamicAnalyzer* dynamicAnalyzer
        -ResponseGenerator* responseGenerator
        +analyzeFiles(path, taskId)
        +detect(jsCode)
        +detectFromHtml(html)
        -executeJavaScriptBlock()
        -performStaticPatternAnalysis()
    }
    
    class DynamicAnalyzer {
        -vector~HookEvent~ capturedEvents
        +recordEvent(event)
        +getHookEvents()
        +getEventsBySeverity(minSeverity)
        +reset()
    }
    
    class TaintTracker {
        -map~string, TaintedValue*~ taintedValues
        -map~string, string~ variableToTaint
        -map~string, set~string~~ propagationGraph
        +createTaintedValue(value, source)
        +taintVariable(varName, taintedValue)
        +propagateTaint(parent, newValue)
        +tracePropagationPath(valueId)
    }
    
    class ChainDetector {
        -TaintTracker* taintTracker
        -map~string, AttackChain~ activeChains
        -vector~AttackChain~ completedChains
        +detectFunctionCall(name, args)
        +generateReport()
        -handleDecoderFunction()
        -handleDangerousFunction()
    }
    
    class Detection {
        +int line
        +string snippet
        +string reason
        +string name
        +int severity
        +map~string, JsValue~ features
        +set~string~ tags
    }
    
    JSAnalyzer --> DynamicAnalyzer
    JSAnalyzer --> ChainTrackerManager
    ChainTrackerManager --> ChainDetector
    ChainDetector --> TaintTracker
    TaintTracker --> TaintedValue
    DynamicAnalyzer --> HookEvent
    JSAnalyzer --> Detection
```

## 8. 실행 시퀀스 (전체 분석 과정)

```mermaid
sequenceDiagram
    participant Main as main.cpp
    participant JSA as JSAnalyzer
    participant QJS as QuickJS
    participant BO as Builtin Objects
    participant DA as DynamicAnalyzer
    participant CD as ChainDetector
    participant TT as TaintTracker
    participant RG as ResponseGenerator
    
    Main->>JSA: analyzeFiles(path, taskId)
    
    JSA->>JSA: 파일 로드 및 파싱
    JSA->>QJS: 런타임 초기화
    JSA->>BO: 브라우저 객체 주입
    
    Note over JSA: 정적 분석
    JSA->>JSA: performStaticPatternAnalysis()
    
    Note over JSA,QJS: 동적 분석
    JSA->>QJS: JS_Eval(jsCode)
    
    loop 각 함수 호출
        QJS->>BO: 함수 실행
        BO->>DA: recordEvent(HookEvent)
        BO->>CD: detectFunctionCall()
        CD->>TT: Taint 확인 및 전파
        TT-->>CD: TaintedValue
        CD->>CD: 체인 생성/확장
        BO->>QJS: 실제 실행
    end
    
    QJS-->>JSA: 실행 완료
    
    JSA->>CD: generateReport()
    CD-->>JSA: AttackChains
    
    JSA->>TT: getStatistics()
    TT-->>JSA: Taint 정보
    
    JSA->>DA: getHookEvents()
    DA-->>JSA: Hook 이벤트들
    
    JSA->>RG: 결과 통합
    RG->>RG: JSON 생성
    RG-->>JSA: JSON 보고서
    
    JSA-->>Main: 분석 완료
```

## 9. 파일 시스템 레이아웃

```
HtmlJSScanner/
│
├── 📁 core/                    # 핵심 분석 엔진
│   ├── JSAnalyzer.h/cpp       # 메인 분석 오케스트레이터
│   ├── DynamicAnalyzer.h/cpp  # Hook 이벤트 수집
│   ├── TaintTracker.h/cpp     # 오염 데이터 추적
│   ├── TaintedValue.h/cpp     # 오염 값 모델
│   ├── DynamicStringTracker.h/cpp  # 문자열 추적
│   ├── StringDeobfuscator.h/cpp    # 디옵스퓨스케이션
│   └── ChainTrackerManager.h/cpp   # 체인 관리
│
├── 📁 chain/                   # 공격 체인 분석
│   ├── ChainDetector.h/cpp    # 체인 자동 탐지
│   ├── AttackChain.h/cpp      # 체인 모델
│   └── ChainStep.h/cpp        # 체인 단계
│
├── 📁 builtin/                 # 브라우저 환경 모킹
│   ├── 📁 helpers/            # 유틸리티
│   │   ├── Base64Utils.h/cpp
│   │   ├── SensitiveKeywordDetector.h/cpp
│   │   └── ...
│   └── 📁 objects/            # 브라우저 객체
│       ├── WindowObject.h/cpp
│       ├── DocumentObject.h/cpp
│       ├── XMLHTTPRequestObject.h/cpp
│       └── ...
│
├── 📁 hooks/                   # Hook 시스템
│   ├── HookType.h             # Hook 타입 정의
│   ├── HookEvent.h/cpp        # Hook 이벤트
│   └── Hook.h                 # Hook 인터페이스
│
├── 📁 parser/                  # 파싱 계층
│   ├── 📁 html/
│   ├── 📁 js/
│   └── 📁 css/
│
├── 📁 model/                   # 데이터 모델
│   ├── Detection.h/cpp
│   ├── JsValueVariant.h/cpp
│   └── DataNode.h/cpp
│
├── 📁 reporters/               # 보고서 생성
│   ├── ResponseGenerator.h/cpp
│   ├── HtmlJsReportWriter.h/cpp
│   └── 📁 metadata/
│
├── 📁 utils/                   # 유틸리티
│   └── Logger.h/cpp
│
├── 📁 test/                    # 테스트 케이스
│   ├── clipboard_hijacking_test.html
│   ├── chain_obfuscator_test.js
│   └── 📁 adam/               # 실제 악성코드 샘플
│
├── 📁 docs/                    # 문서
│   ├── COMPREHENSIVE_PROJECT_REPORT.md  ⬅️ 본 보고서
│   ├── PROJECT_SUMMARY.md
│   ├── ARCHITECTURE_DIAGRAMS.md         ⬅️ 현재 파일
│   └── ...
│
├── main.cpp                    # 프로그램 진입점
├── HtmlJSScanner.h/cpp        # DLL 인터페이스
├── pch.h                       # 사전 컴파일 헤더
├── CMakeLists.txt             # CMake 빌드
└── HtmlJSScanner.sln          # Visual Studio 솔루션
```

---

## 10. 탐지 엔진 상태 머신

```mermaid
stateDiagram-v2
    [*] --> Initialized: 초기화
    
    Initialized --> ParsingHTML: HTML 로드
    ParsingHTML --> ExtractingJS: JavaScript 추출
    
    ExtractingJS --> StaticAnalysis: 정적 분석 시작
    StaticAnalysis --> DynamicAnalysis: 동적 분석 시작
    
    state DynamicAnalysis {
        [*] --> ExecutingJS
        ExecutingJS --> HookCapture: Hook 트리거
        HookCapture --> TaintTracking: Taint 추적
        TaintTracking --> ChainDetection: 체인 탐지
        ChainDetection --> ExecutingJS: 계속 실행
        ChainDetection --> [*]: 실행 완료
    }
    
    DynamicAnalysis --> PostAnalysis: 후처리
    
    state PostAnalysis {
        [*] --> MergeResults
        MergeResults --> CalculateSeverity
        CalculateSeverity --> GenerateReport
        GenerateReport --> [*]
    }
    
    PostAnalysis --> [*]: 분석 완료
```

---

*이 다이어그램들은 HtmlJSScanner 프로젝트의 구조와 동작 원리를 시각적으로 표현합니다.*

**버전**: 1.0.0  
**마지막 업데이트**: 2025-01-03
