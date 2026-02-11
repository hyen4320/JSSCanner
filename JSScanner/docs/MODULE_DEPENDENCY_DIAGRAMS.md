# JSScanner - 모듈 종속관계 다이어그램

## 1. 전체 시스템 아키텍처

```mermaid
graph TB
    subgraph "Entry Point"
        A[main.cpp]
    end
    
    subgraph "Core Engine"
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
        M[GlobalObject]
        N[NavigatorObject]
    end
    
    subgraph "Output"
        O[ResponseGenerator]
        P[HtmlJsReportWriter]
        Q[JSON Report]
    end
    
    A --> B
    B --> C
    B --> D
    B --> E
    
    C --> J
    C --> K
    C --> L
    C --> M
    C --> N
    
    E --> F
    F --> G
    D --> H
    H --> I
    
    B --> O
    O --> P
    P --> Q
    
    style A fill:#e3f2fd
    style B fill:#fff3e0
    style F fill:#f3e5f5
    style O fill:#e8f5e9
    style Q fill:#ffebee
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

## 9. 탐지 엔진 상태 머신

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

## 10. 악성코드 탐지 플로우 (클립보드 하이재킹 예시)

```mermaid
flowchart TD
    START([악성 JS 실행]) --> CLIP[navigator.clipboard.writeText 호출]
    
    CLIP --> HOOK[NavigatorObject::js_clipboard_writeText]
    
    HOOK --> RECORD[DynamicAnalyzer::recordEvent]
    RECORD --> EVENT[HookEvent 생성<br/>type: CLIPBOARD_OPERATION]
    
    HOOK --> TRACK[DynamicStringTracker::trackString]
    
    TRACK --> PATTERN{악성 패턴<br/>매칭?}
    
    PATTERN -->|cmd /c| DETECT1[🚨 MALICIOUS_COMMAND]
    PATTERN -->|powershell| DETECT2[🚨 MALICIOUS_COMMAND]
    PATTERN -->|wscript| DETECT3[🚨 MALICIOUS_COMMAND]
    PATTERN -->|CreateObject| DETECT4[🚨 MALICIOUS_COMMAND]
    
    DETECT1 --> SEVERE[SensitiveStringEvent 생성]
    DETECT2 --> SEVERE
    DETECT3 --> SEVERE
    DETECT4 --> SEVERE
    
    SEVERE --> FINDING[Detection 추가<br/>severity: 10<br/>name: clipboard_hijacking]
    
    FINDING --> REPORT[JSON 보고서에 포함]
    REPORT --> END([분석 완료])
    
    style START fill:#4caf50
    style CLIP fill:#ff9800
    style DETECT1 fill:#f44336
    style DETECT2 fill:#f44336
    style DETECT3 fill:#f44336
    style DETECT4 fill:#f44336
    style FINDING fill:#ff1744
    style END fill:#4caf50
```

---

**다이어그램 버전**: 1.0  
**마지막 업데이트**: 2025-01-03
