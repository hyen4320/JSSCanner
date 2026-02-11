# JSScanner 상세 탐지 과정 다이어그램

## 1. 전체 탐지 플로우 (상세)

```mermaid
flowchart TD
    START([파일 입력<br/>HTML/JS]) --> LOAD[파일 로드]
    LOAD --> CHECK{파일 타입<br/>확인}
    
    CHECK -->|HTML| HTML_PARSE[HTML 파싱<br/>TagParser]
    CHECK -->|JS| JS_DIRECT[JavaScript 직접 분석]
    
    HTML_PARSE --> EXTRACT[JavaScript 코드 추출<br/>inline/external]
    EXTRACT --> JS_DIRECT
    
    JS_DIRECT --> INIT[QuickJS 초기화<br/>브라우저 객체 주입]
    
    INIT --> STATIC[정적 분석<br/>패턴 매칭]
    STATIC --> DYNAMIC[동적 분석<br/>코드 실행]
    
    subgraph "정적 분석 과정"
        STATIC --> PATTERN[민감 패턴 탐지<br/>SensitiveKeywordDetector]
        PATTERN --> URL_EXTRACT[URL 추출<br/>UrlCollector]
        URL_EXTRACT --> VARIABLE_SCAN[변수 스캔<br/>VariableScanner]
    end
    
    subgraph "동적 분석 과정"
        DYNAMIC --> EXEC[JS_Eval 실행]
        EXEC --> HOOK_TRIGGER{함수 호출<br/>감지}
        
        HOOK_TRIGGER -->|eval/Function| DANGEROUS_1[위험 함수 탐지]
        HOOK_TRIGGER -->|atob/unescape| DECODER_1[디코더 함수 탐지]
        HOOK_TRIGGER -->|fetch/XMLHttpRequest| NETWORK_1[네트워크 함수 탐지]
        
        DANGEROUS_1 --> RECORD_EVENT[DynamicAnalyzer<br/>이벤트 기록]
        DECODER_1 --> RECORD_EVENT
        NETWORK_1 --> RECORD_EVENT
        
        RECORD_EVENT --> TAINT_CHECK[Taint 추적<br/>TaintTracker]
        TAINT_CHECK --> CHAIN_CHECK[공격 체인 탐지<br/>ChainDetector]
        CHAIN_CHECK --> STRING_TRACK[문자열 추적<br/>DynamicStringTracker]
        
        STRING_TRACK --> DEOBFUSCATE[난독화 해제<br/>StringDeobfuscator]
    end
    
    DEOBFUSCATE --> MERGE[결과 통합]
    VARIABLE_SCAN --> MERGE
    
    MERGE --> SEVERITY[위험도 계산<br/>Severity Scoring]
    SEVERITY --> REPORT[보고서 생성<br/>ResponseGenerator]
    REPORT --> JSON[JSON 출력<br/>HtmlJsReportWriter]
    
    JSON --> END([탐지 완료])
    
    style START fill:#4caf50,color:#fff
    style STATIC fill:#2196f3,color:#fff
    style DYNAMIC fill:#ff9800,color:#fff
    style TAINT_CHECK fill:#e91e63,color:#fff
    style CHAIN_CHECK fill:#9c27b0,color:#fff
    style END fill:#f44336,color:#fff
```

## 2. Hook 기반 탐지 메커니즘 (세부)

```mermaid
sequenceDiagram
    autonumber
    participant JS as JavaScript 코드
    participant QJS as QuickJS 엔진
    participant Hook as Hooked 함수
    participant DA as DynamicAnalyzer
    participant TT as TaintTracker
    participant CD as ChainDetector
    participant DST as DynamicStringTracker
    participant SD as StringDeobfuscator
    
    Note over JS,QJS: === 실행 시작 ===
    JS->>QJS: eval("atob('bWFsaWNpb3Vz')")
    QJS->>Hook: GlobalObject::eval()
    
    Note over Hook: 함수 호출 전처리
    Hook->>DA: recordEvent(EVAL, args)
    Hook->>TT: 인자의 Taint 확인
    alt 인자가 tainted
        TT-->>Hook: TaintedValue 반환
        Hook->>CD: detectFunctionCall(eval, tainted)
        CD->>CD: 공격 체인 생성/확장
    else 인자가 clean
        TT-->>Hook: null
    end
    
    Note over Hook: 실제 함수 실행
    Hook->>QJS: 원본 eval 호출
    QJS->>Hook: 실행 결과
    
    Note over Hook: 함수 호출 후처리
    Hook->>DST: trackString(결과)
    DST->>SD: deobfuscate(결과)
    SD-->>DST: 난독화 해제된 문자열
    
    Hook->>TT: propagateTaint(parent, 결과)
    TT->>TT: 전파 그래프 업데이트
    
    Hook->>JS: 결과 반환
    
    Note over JS,SD: === 다음 호출 ===
    JS->>QJS: fetch(taintedUrl)
    QJS->>Hook: WindowObject::fetch()
    Hook->>DA: recordEvent(FETCH, taintedUrl)
    Hook->>CD: detectFunctionCall(fetch, tainted)
    CD->>CD: 위험한 체인 완성!
    CD->>DA: 체인 탐지 결과 기록
```

## 3. Taint 전파 상세 과정

```mermaid
graph TB
    subgraph "1단계: Taint 생성"
        A1[외부 입력 소스] -->|window.location.search| B1[createTaintedValue]
        B1 --> C1[TaintedValue 생성<br/>ID: taint_001<br/>Level: 8<br/>Source: location.search]
    end
    
    subgraph "2단계: 변수 할당"
        C1 -->|var param = ...| D1[taintVariable]
        D1 --> E1[변수-Taint 매핑<br/>param → taint_001]
    end
    
    subgraph "3단계: 문자열 연산"
        E1 -->|var url = 'api/' + param| F1[propagateTaint]
        F1 --> G1[새 TaintedValue<br/>ID: taint_002<br/>Parent: taint_001<br/>Level: 8]
        G1 --> H1[변수 업데이트<br/>url → taint_002]
    end
    
    subgraph "4단계: 전파 그래프"
        G1 -.->|propagationGraph| I1[taint_001 → taint_002]
        H1 -.->|variableToTaint| J1[url → taint_002]
    end
    
    subgraph "5단계: 위험 함수 도달"
        H1 -->|fetch(url)| K1{위험 함수 검사}
        K1 -->|tainted| L1[🚨 Detection 생성<br/>Type: DATA_EXFILTRATION<br/>Severity: 9]
        K1 -->|clean| M1[정상 동작]
    end
    
    subgraph "6단계: 전파 경로 추적"
        L1 --> N1[tracePropagationPath]
        N1 --> O1[taint_002 → taint_001 → location.search]
        O1 --> P1[완전한 전파 경로<br/>보고서에 포함]
    end
    
    style A1 fill:#4caf50
    style C1 fill:#fff176
    style G1 fill:#fff176
    style L1 fill:#f44336
    style O1 fill:#ff9800
```

## 4. 공격 체인 탐지 알고리즘

```mermaid
flowchart TD
    START([함수 호출 감지]) --> GET_TAINT[인자의 Taint 확인]
    
    GET_TAINT --> CHECK_TYPE{함수 타입 확인}
    
    CHECK_TYPE -->|디코더| DECODER[atob/unescape/<br/>decodeURIComponent]
    CHECK_TYPE -->|난독화 해제| DEOBF[eval/Function/<br/>document.write]
    CHECK_TYPE -->|위험 함수| DANGER[fetch/XMLHttpRequest/<br/>WebSocket/Worker]
    CHECK_TYPE -->|기타| IGNORE[무시]
    
    DECODER --> CHECK_ACTIVE{활성 체인 존재?}
    CHECK_ACTIVE -->|No| CREATE_CHAIN[새 체인 생성<br/>AttackChain]
    CHECK_ACTIVE -->|Yes| EXTEND_CHAIN[기존 체인 확장]
    
    CREATE_CHAIN --> ADD_STEP1[ChainStep 추가<br/>Type: DECODER]
    EXTEND_CHAIN --> ADD_STEP1
    
    ADD_STEP1 --> STORE_ACTIVE[activeChains에 저장<br/>Key: taintId]
    
    DEOBF --> FIND_CHAIN{해당 taint의<br/>체인 존재?}
    FIND_CHAIN -->|Yes| ADD_STEP2[ChainStep 추가<br/>Type: DEOBFUSCATOR]
    FIND_CHAIN -->|No| CREATE_SINGLE[단일 탐지 생성]
    
    ADD_STEP2 --> UPDATE_CHAIN[체인 업데이트]
    
    DANGER --> FIND_CHAIN2{해당 taint의<br/>체인 존재?}
    FIND_CHAIN2 -->|Yes| COMPLETE[체인 완성!<br/>completedChains에 이동]
    FIND_CHAIN2 -->|No| CREATE_SINGLE2[단일 탐지 생성]
    
    COMPLETE --> VERIFY{인과관계 검증}
    VERIFY -->|Valid| GENERATE[Detection 생성<br/>Severity 계산]
    VERIFY -->|Invalid| DISCARD[체인 폐기]
    
    GENERATE --> END([탐지 완료])
    CREATE_SINGLE --> END
    CREATE_SINGLE2 --> END
    DISCARD --> END
    IGNORE --> END
    
    style START fill:#4caf50
    style DECODER fill:#2196f3
    style DEOBF fill:#ff9800
    style DANGER fill:#f44336
    style COMPLETE fill:#9c27b0
    style GENERATE fill:#e91e63
```

## 5. 문자열 추적 및 난독화 해제

```mermaid
sequenceDiagram
    participant Code as JavaScript
    participant DST as DynamicStringTracker
    participant SD as StringDeobfuscator
    participant Results as 추적 결과
    
    Note over Code,DST: 난독화된 문자열 감지
    Code->>DST: trackString("bWFsaWNpb3Vz")
    DST->>DST: 문자열 저장<br/>trackedStrings
    
    DST->>SD: deobfuscate("bWFsaWNpb3Vz")
    
    Note over SD: Base64 패턴 감지
    SD->>SD: isBase64Pattern()
    SD->>SD: Base64Utils::decode()
    SD-->>DST: "malicious"
    
    DST->>DST: 매핑 저장<br/>originalToDeobf
    DST-->>Results: deobfuscated: "malicious"
    
    Note over Code,DST: 난독화된 코드 실행
    Code->>DST: trackString("ZXZhbChhdG9iKCdZV3hsY25')...")
    DST->>SD: deobfuscate(...)
    
    Note over SD: 다층 난독화 감지
    SD->>SD: 1차: Base64 디코딩
    SD->>SD: 2차: 재귀 디옵스퓨스케이트
    SD->>SD: 3차: 유니코드 변환
    SD-->>DST: "eval(atob('alert'))"
    
    DST->>DST: 디옵스케이션 레벨 기록
    DST-->>Results: level: 3, final: "eval..."
    
    Note over Code,Results: Hex 인코딩 처리
    Code->>DST: trackString("\\x65\\x76\\x61\\x6c")
    DST->>SD: deobfuscate(...)
    SD->>SD: hexToString()
    SD-->>DST: "eval"
    DST-->>Results: type: HEX_ENCODING
```

## 6. 정적 분석 상세 과정

```mermaid
flowchart LR
    START([JavaScript 코드]) --> KEYWORD[키워드 탐지<br/>SensitiveKeywordDetector]
    
    subgraph "민감 키워드 스캔"
        KEYWORD --> CHECK_EVAL[eval 패턴]
        KEYWORD --> CHECK_FUNC[Function 생성자]
        KEYWORD --> CHECK_EXEC[exec/execScript]
        KEYWORD --> CHECK_BASE64[atob/btoa]
        KEYWORD --> CHECK_UNESCAPE[unescape/decode]
        
        CHECK_EVAL --> DETECT1{발견?}
        CHECK_FUNC --> DETECT2{발견?}
        CHECK_EXEC --> DETECT3{발견?}
        CHECK_BASE64 --> DETECT4{발견?}
        CHECK_UNESCAPE --> DETECT5{발견?}
        
        DETECT1 -->|Yes| RECORD1[Detection 기록<br/>Severity: 7]
        DETECT2 -->|Yes| RECORD2[Detection 기록<br/>Severity: 7]
        DETECT3 -->|Yes| RECORD3[Detection 기록<br/>Severity: 8]
        DETECT4 -->|Yes| RECORD4[Detection 기록<br/>Severity: 4]
        DETECT5 -->|Yes| RECORD5[Detection 기록<br/>Severity: 5]
    end
    
    START --> URL_SCAN[URL 스캔<br/>UrlCollector]
    
    subgraph "URL 추출"
        URL_SCAN --> REGEX[정규식 매칭]
        REGEX --> HTTP[http:// URL]
        REGEX --> HTTPS[https:// URL]
        REGEX --> WS[ws:// URL]
        REGEX --> DATA[data: URL]
        
        HTTP --> URL_STORE[URL 저장]
        HTTPS --> URL_STORE
        WS --> URL_STORE
        DATA --> URL_STORE
    end
    
    START --> VAR_SCAN[변수 스캔<br/>VariableScanner]
    
    subgraph "변수 분석"
        VAR_SCAN --> FIND_VAR[변수 선언 탐지]
        FIND_VAR --> ANALYZE_TYPE[타입 분석]
        ANALYZE_TYPE --> CHECK_SUSP{의심스러운<br/>패턴?}
        CHECK_SUSP -->|Yes| FLAG[플래그 설정]
    end
    
    RECORD1 --> MERGE
    RECORD2 --> MERGE
    RECORD3 --> MERGE
    RECORD4 --> MERGE
    RECORD5 --> MERGE
    URL_STORE --> MERGE
    FLAG --> MERGE
    
    MERGE[결과 통합] --> OUTPUT([정적 분석 완료])
    
    style START fill:#4caf50
    style KEYWORD fill:#2196f3
    style URL_SCAN fill:#ff9800
    style VAR_SCAN fill:#9c27b0
    style OUTPUT fill:#f44336
```

## 7. 브라우저 객체 시뮬레이션

```mermaid
graph TB
    subgraph "Global Scope"
        GLOBAL[QuickJS Global Object]
    end
    
    subgraph "Core Objects"
        GLOBAL --> WINDOW[WindowObject<br/>location, navigator, alert]
        GLOBAL --> DOCUMENT[DocumentObject<br/>createElement, getElementById]
        GLOBAL --> CONSOLE[ConsoleObject<br/>log, error, warn]
    end
    
    subgraph "String & Encoding"
        GLOBAL --> STRING_OBJ[StringObject<br/>charAt, substring]
        GLOBAL --> TEXTDECODER[TextDecoderObject<br/>decode]
        GLOBAL --> BASE64[Base64 Functions<br/>atob, btoa]
    end
    
    subgraph "Data Structures"
        GLOBAL --> ARRAY[ArrayObject<br/>push, pop, slice]
        GLOBAL --> REGEXP[RegExpObject<br/>test, exec, match]
        GLOBAL --> MATH[MathObject<br/>random, floor]
    end
    
    subgraph "Storage"
        WINDOW --> LOCALSTORAGE[LocalStorageObject<br/>setItem, getItem]
        DOCUMENT --> ELEMENT[ElementObject<br/>innerHTML, onclick]
    end
    
    subgraph "Network & APIs"
        GLOBAL --> XHR[XMLHTTPRequestObject<br/>open, send]
        GLOBAL --> FETCH[Fetch API<br/>fetch, Response]
        GLOBAL --> WS[WebSocketObject<br/>send, onmessage]
    end
    
    subgraph "Modern APIs"
        GLOBAL --> FORMDATA[FormDataObject<br/>append, get]
        GLOBAL --> BLOB[BlobObject<br/>slice, text]
        GLOBAL --> WORKER[WorkerObject<br/>postMessage]
        GLOBAL --> WASM[WebAssemblyObject<br/>instantiate]
        GLOBAL --> INDEXEDDB[IndexedDBObject<br/>open, transaction]
    end
    
    subgraph "Third-party"
        GLOBAL --> JQUERY[JQueryObject<br/>$, ajax]
    end
    
    subgraph "Hook Points"
        XHR -.->|Hook| HOOK1[DynamicAnalyzer]
        FETCH -.->|Hook| HOOK1
        WS -.->|Hook| HOOK1
        BASE64 -.->|Hook| HOOK1
        ELEMENT -.->|Hook| HOOK1
    end
    
    HOOK1 --> RECORD[이벤트 기록 및 분석]
    
    style GLOBAL fill:#4caf50
    style WINDOW fill:#2196f3
    style DOCUMENT fill:#2196f3
    style XHR fill:#f44336
    style FETCH fill:#f44336
    style HOOK1 fill:#ff9800
```

## 8. 결과 생성 및 리포팅

```mermaid
flowchart TD
    START([분석 완료]) --> COLLECT[모든 Detection 수집]
    
    COLLECT --> DYNAMIC_RES[동적 분석 결과<br/>DynamicAnalyzer]
    COLLECT --> CHAIN_RES[체인 탐지 결과<br/>ChainDetector]
    COLLECT --> TAINT_RES[Taint 추적 결과<br/>TaintTracker]
    COLLECT --> STRING_RES[문자열 분석 결과<br/>DynamicStringTracker]
    COLLECT --> STATIC_RES[정적 분석 결과]
    
    DYNAMIC_RES --> MERGE[결과 통합<br/>ResponseGenerator]
    CHAIN_RES --> MERGE
    TAINT_RES --> MERGE
    STRING_RES --> MERGE
    STATIC_RES --> MERGE
    
    MERGE --> DEDUPE[중복 제거]
    DEDUPE --> SORT[위험도 정렬]
    
    SORT --> BUILD_META[메타데이터 구성]
    BUILD_META --> BUILD_DETECTIONS[탐지 목록 구성]
    BUILD_DETECTIONS --> BUILD_CHAINS[체인 정보 구성]
    BUILD_CHAINS --> BUILD_TAINT[Taint 그래프 구성]
    BUILD_TAINT --> BUILD_STATS[통계 정보 구성]
    
    BUILD_STATS --> JSON_GEN[JSON 생성<br/>HtmlJsReportWriter]
    
    subgraph "JSON 구조"
        JSON_GEN --> META[metadata:<br/>taskId, timestamp, version]
        JSON_GEN --> SUMMARY[summary:<br/>totalDetections, maxSeverity]
        JSON_GEN --> DETECTIONS[detections: [<br/>line, snippet, reason, severity<br/>]]
        JSON_GEN --> CHAINS[attackChains: [<br/>steps, severity, taintPath<br/>]]
        JSON_GEN --> TAINTS[taintTracking:<br/>propagationGraph]
        JSON_GEN --> HOOK_EVENTS[hookEvents: [<br/>functionName, args, result<br/>]]
    end
    
    JSON_GEN --> SAVE[파일 저장]
    SAVE --> OUTPUT([JSON 파일 출력])
    
    style START fill:#4caf50
    style MERGE fill:#2196f3
    style JSON_GEN fill:#ff9800
    style OUTPUT fill:#f44336
```

## 9. 위험도 계산 메커니즘

```mermaid
flowchart TD
    START([Detection 생성]) --> BASE_SCORE[기본 점수 설정]
    
    BASE_SCORE --> CHECK_TYPE{Detection 타입}
    
    CHECK_TYPE -->|EVAL| SCORE1[Base: 7]
    CHECK_TYPE -->|DYNAMIC_CODE| SCORE2[Base: 7]
    CHECK_TYPE -->|NETWORK_REQUEST| SCORE3[Base: 6]
    CHECK_TYPE -->|BASE64_DECODE| SCORE4[Base: 4]
    CHECK_TYPE -->|SUSPICIOUS_PATTERN| SCORE5[Base: 5]
    
    SCORE1 --> TAINT_CHECK
    SCORE2 --> TAINT_CHECK
    SCORE3 --> TAINT_CHECK
    SCORE4 --> TAINT_CHECK
    SCORE5 --> TAINT_CHECK
    
    TAINT_CHECK{Taint 데이터<br/>사용?}
    TAINT_CHECK -->|Yes| ADD_TAINT[+2점<br/>오염된 데이터]
    TAINT_CHECK -->|No| CHAIN_CHECK
    
    ADD_TAINT --> CHAIN_CHECK{공격 체인<br/>일부?}
    CHAIN_CHECK -->|Yes| ADD_CHAIN[+2점<br/>체인 공격]
    CHAIN_CHECK -->|No| OBFUSC_CHECK
    
    ADD_CHAIN --> OBFUSC_CHECK{난독화<br/>사용?}
    OBFUSC_CHECK -->|Yes| ADD_OBFUSC[+1점<br/>난독화]
    OBFUSC_CHECK -->|No| EXTERNAL_CHECK
    
    ADD_OBFUSC --> EXTERNAL_CHECK{외부 통신?}
    EXTERNAL_CHECK -->|Yes| ADD_EXTERNAL[+1점<br/>외부 연결]
    EXTERNAL_CHECK -->|No| FINAL_CALC
    
    ADD_EXTERNAL --> FINAL_CALC[최종 점수 계산]
    
    FINAL_CALC --> CLASSIFY{분류}
    CLASSIFY -->|9-10| CRITICAL[🔴 Critical]
    CLASSIFY -->|7-8| HIGH[🟠 High]
    CLASSIFY -->|5-6| MEDIUM[🟡 Medium]
    CLASSIFY -->|3-4| LOW[🟢 Low]
    CLASSIFY -->|0-2| INFO[⚪ Info]
    
    CRITICAL --> END([Severity 확정])
    HIGH --> END
    MEDIUM --> END
    LOW --> END
    INFO --> END
    
    style START fill:#4caf50
    style TAINT_CHECK fill:#e91e63
    style CHAIN_CHECK fill:#9c27b0
    style CRITICAL fill:#f44336
    style HIGH fill:#ff9800
    style MEDIUM fill:#ffc107
```

## 10. 실제 악성 코드 분석 예시

```mermaid
sequenceDiagram
    autonumber
    participant Sample as 악성 샘플
    participant JSA as JSAnalyzer
    participant Static as 정적 분석
    participant QJS as QuickJS
    participant Hooks as Hook 시스템
    participant TT as TaintTracker
    participant CD as ChainDetector
    participant Report as 보고서
    
    Note over Sample: 난독화된 악성 코드
    Sample->>JSA: 파일 로드
    JSA->>Static: 정적 분석 시작
    
    Static->>Static: atob 패턴 탐지
    Static->>Static: eval 패턴 탐지
    Static-->>JSA: Detection: suspicious_base64
    
    JSA->>QJS: 동적 분석 시작
    QJS->>Sample: 코드 실행
    
    Sample->>Hooks: atob("bWFsaWNpb3Vz...")
    Hooks->>CD: DECODER 함수 감지
    CD->>CD: 새 공격 체인 시작
    Hooks->>TT: 결과를 Taint로 표시
    TT-->>Hooks: taint_001 생성
    
    Sample->>Hooks: eval(taintedString)
    Hooks->>CD: DEOBFUSCATOR 감지
    CD->>TT: taint_001 확인
    CD->>CD: 체인 확장
    
    Sample->>Hooks: document.location.href
    Hooks->>TT: EXTERNAL_INPUT
    TT-->>Hooks: taint_002 생성
    
    Sample->>Hooks: fetch(tainted_url)
    Hooks->>CD: DANGEROUS_FUNCTION 감지
    CD->>TT: taint 체인 확인
    CD->>CD: 체인 완성!
    
    CD-->>Report: AttackChain: DECODER→DEOBF→EXFIL
    TT-->>Report: Taint Graph: 전파 경로
    Hooks-->>Report: Hook Events: 전체 호출 기록
    
    Report->>Report: Severity: 9 (Critical)
    Report->>Report: JSON 생성
    
    Note over Report: 탐지 완료<br/>악성 코드로 판단
```

## 11. 성능 최적화 및 에러 처리

```mermaid
flowchart TD
    START([분석 시작]) --> TIMEOUT_SET[타임아웃 설정<br/>기본: 30초]
    
    TIMEOUT_SET --> TRY_EXEC{코드 실행}
    
    TRY_EXEC -->|Success| NORMAL_FLOW[정상 분석 진행]
    TRY_EXEC -->|Exception| CATCH_ERR[예외 포착]
    TRY_EXEC -->|Timeout| CATCH_TIMEOUT[타임아웃 처리]
    
    CATCH_ERR --> LOG_ERR[에러 로깅<br/>Logger::error]
    CATCH_TIMEOUT --> LOG_TIMEOUT[타임아웃 로깅]
    
    LOG_ERR --> PARTIAL_RESULT[부분 결과 반환]
    LOG_TIMEOUT --> PARTIAL_RESULT
    
    NORMAL_FLOW --> MUTEX_CHECK{멀티스레드?}
    MUTEX_CHECK -->|Yes| LOCK[g_quickjs_mutex<br/>락 획득]
    MUTEX_CHECK -->|No| CONTINUE
    
    LOCK --> CONTINUE[분석 계속]
    
    CONTINUE --> MEM_CHECK{메모리 체크}
    MEM_CHECK -->|Over Limit| CLEANUP[메모리 정리]
    MEM_CHECK -->|OK| PROCESS
    
    CLEANUP --> PROCESS[분석 처리]
    
    PROCESS --> CONTEXT_SAVE[컨텍스트 저장]
    CONTEXT_SAVE --> UNLOCK{락 해제 필요?}
    
    UNLOCK -->|Yes| RELEASE[뮤텍스 해제]
    UNLOCK -->|No| FINALIZE
    
    RELEASE --> FINALIZE[결과 최종화]
    PARTIAL_RESULT --> FINALIZE
    
    FINALIZE --> END([분석 완료])
    
    style START fill:#4caf50
    style CATCH_ERR fill:#f44336
    style CATCH_TIMEOUT fill:#ff9800
    style LOCK fill:#2196f3
    style END fill:#4caf50
```

---

## 요약

이 다이어그램들은 JSScanner 프로젝트의 **탐지 과정**을 단계별로 상세하게 보여줍니다:

1. **전체 플로우**: 파일 입력부터 JSON 출력까지의 전체 과정
2. **Hook 메커니즘**: 함수 호출 감지 및 분석 과정
3. **Taint 전파**: 오염된 데이터의 추적 과정
4. **공격 체인**: 다단계 공격 탐지 알고리즘
5. **문자열 추적**: 난독화 해제 과정
6. **정적 분석**: 키워드 및 패턴 기반 탐지
7. **객체 시뮬레이션**: 브라우저 환경 모킹
8. **리포팅**: 결과 생성 및 JSON 구성
9. **위험도 계산**: Severity 점수 산정
10. **실제 예시**: 악성 코드 분석 시나리오
11. **에러 처리**: 예외 및 성능 관리

**핵심 특징**:
- 정적 + 동적 분석의 하이브리드 접근
- Taint 기반 데이터 흐름 추적
- 다단계 공격 체인 자동 재구성
- 난독화 자동 해제
- 실시간 Hook 기반 모니터링

**버전**: 1.0.0  
**작성일**: 2025-01-10
