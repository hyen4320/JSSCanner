# HtmlJSScanner - JavaScript Malware Detection System

> C++ 기반의 고성능 JavaScript 악성코드 탐지 시스템  
> QuickJS 엔진을 활용한 하이브리드 분석 (정적 + 동적)

[![Language](https://img.shields.io/badge/Language-C++-blue.svg)](https://isocpp.org/)
[![Engine](https://img.shields.io/badge/Engine-QuickJS-green.svg)](https://bellard.org/quickjs/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-red.svg)](docs/COMPREHENSIVE_PROJECT_REPORT.md)

---

## 🎯 프로젝트 개요

**HtmlJSScanner**는 웹 기반 JavaScript 악성코드를 탐지하고 분석하는 강력한 보안 도구입니다.

### 핵심 기능

- ✅ **하이브리드 분석**: 정적 패턴 매칭 + 동적 실행 분석
- ✅ **공격 체인 재구성**: 다단계 공격 패턴 자동 추적 (atob → eval → fetch)
- ✅ **Taint 추적**: 오염된 데이터의 전파 경로 분석
- ✅ **브라우저 환경 시뮬레이션**: 11개 브라우저 API 모킹
- ✅ **실시간 Hook 모니터링**: 위험 함수 호출 감지
- ✅ **클립보드 하이재킹 탐지**: 가짜 CAPTCHA 공격 차단 ⚠️

---

## 🚀 빠른 시작

### 빌드

```bash
# Windows (Visual Studio)
msbuild HtmlJSScanner.sln /p:Configuration=ReleaseMT /p:Platform=x64

# CMake (크로스 플랫폼)
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

### 실행

```bash
# 로컬 파일 분석
HtmlJSScanner.exe "path/to/malicious.html" task_001

# URL 분석
HtmlJSScanner.exe "https://example.com/malicious.html" task_002

# 디버그 모드
HtmlJSScanner.exe "test.js" task_003 --debug
```

### DLL 통합 (서버)

```cpp
// DLL 로드 및 사용
typedef void (*ScanFunc)(const char*, int);
HMODULE hModule = LoadLibrary("HtmlJSScanner.dll");
ScanFunc scan = (ScanFunc)GetProcAddress(hModule, "ScanHtmlJS");
scan("https://malicious.com", 12345);
```

---

## 📊 탐지 능력

### 악성코드 유형 (12가지)

| 공격 유형 | 설명 | 심각도 |
|-----------|------|--------|
| **클립보드 하이재킹** | 가짜 CAPTCHA를 통한 악성 명령어 주입 | 🔴 CRITICAL |
| **다단계 공격 체인** | atob → eval → fetch 연결 공격 | 🟠 HIGH |
| **Taint 전파** | 외부 입력 → 위험 함수 도달 | 🟠 HIGH |
| **eval/Function 악용** | 동적 코드 실행 | 🟠 HIGH |
| **데이터 유출** | 비밀번호, 토큰, 쿠키 수집 | 🟠 HIGH |
| **DOM 조작** | XSS, innerHTML 인젝션 | 🟡 MEDIUM |
| **피싱 리다이렉트** | 가짜 사이트 자동 이동 | 🟡 MEDIUM |
| **난독화** | Base64, Hex, XOR 인코딩 | 🟡 MEDIUM |
| **배열 셔플** | javascript-obfuscator 출력 | 🟡 MEDIUM |
| **스크립트 인젝션** | VBScript Execute 패턴 | 🟡 MEDIUM |
| **환경 탐지** | 안티 샌드박스 기법 | 🟢 LOW |
| **IIFE 패턴** | 스코프 은닉 | 🟢 LOW |

### 탐지 통계

- **True Positive Rate**: ~95%
- **False Positive Rate**: ~5-10%
- **지원 난독화**: Base64, Hex, XOR, 배열 셔플, IIFE

---

## 🏗️ 아키텍처

### 시스템 구조

```
main.cpp
  └─> JSAnalyzer (분석 엔진)
      ├─> DynamicAnalyzer (Hook 이벤트 수집)
      ├─> ChainDetector (공격 체인 추적)
      ├─> TaintTracker (오염 데이터 추적)
      ├─> DynamicStringTracker (문자열 추적)
      └─> ResponseGenerator (JSON 보고서)
```

### 주요 컴포넌트

| 컴포넌트 | 역할 |
|----------|------|
| **JSAnalyzer** | 전체 분석 프로세스 제어 |
| **DynamicAnalyzer** | 런타임 Hook 이벤트 수집 |
| **ChainDetector** | 다단계 공격 체인 재구성 |
| **TaintTracker** | 오염 데이터 전파 경로 추적 |
| **Builtin Objects** | 브라우저 API 모킹 (11개 객체) |
| **StringDeobfuscator** | Base64, Hex, XOR 디코딩 |

---

## 📂 프로젝트 구조

```
HtmlJSScanner/
├── core/               # 핵심 분석 엔진
├── chain/              # 공격 체인 분석
├── builtin/            # 브라우저 환경 모킹
│   ├── helpers/        # 유틸리티
│   └── objects/        # API 객체 (Window, Document 등)
├── hooks/              # Hook 시스템
├── parser/             # HTML/JS/CSS 파싱
├── model/              # 데이터 모델
├── reporters/          # 보고서 생성
├── test/               # 테스트 케이스
└── docs/               # 📚 문서
    ├── COMPREHENSIVE_PROJECT_REPORT.md  # 종합 보고서
    ├── PROJECT_SUMMARY.md               # 요약본
    ├── ARCHITECTURE_DIAGRAMS.md         # 아키텍처 다이어그램
    ├── CLIPBOARD_HIJACKING_DETECTION.md # 클립보드 하이재킹
    └── ...
```

---

## 📚 문서

### 핵심 문서

1. **[종합 프로젝트 보고서](docs/COMPREHENSIVE_PROJECT_REPORT.md)** ⭐
   - 전체 시스템 아키텍처
   - 탐지 가능한 공격 유형 (12가지)
   - 컴포넌트별 상세 설명
   - 탐지 프로세스 플로우
   - 파일/디렉토리 역할
   - 성능 특성 및 제한사항

2. **[프로젝트 요약본](docs/PROJECT_SUMMARY.md)**
   - 빠른 참조용 요약
   - 주요 기능 한눈에 보기
   - 핵심 통계 및 성능

3. **[아키텍처 다이어그램](docs/ARCHITECTURE_DIAGRAMS.md)**
   - 10개 이상의 시각적 다이어그램
   - 시스템 구조, 데이터 흐름
   - Hook 시스템, Taint 추적
   - 공격 체인 재구성 과정

4. **[클립보드 하이재킹 탐지](docs/CLIPBOARD_HIJACKING_DETECTION.md)**
   - 가짜 CAPTCHA 공격 상세
   - 탐지 메커니즘
   - 테스트 방법

### 추가 문서

- **[코어 아키텍처](docs/core-architecture.md)**: 핵심 설계 원리
- **[마이그레이션 가이드](docs/MIGRATION.md)**: 버전 업그레이드

---

## 🧪 테스트

### 테스트 케이스

```bash
# 1. 클립보드 하이재킹
HtmlJSScanner.exe "test/clipboard_hijacking_test.html" test_clipboard

# 2. 공격 체인
HtmlJSScanner.exe "test/chain_obfuscator_test.js" test_chain

# 3. 동적 URL
HtmlJSScanner.exe "test/test_dynamic_url.js" test_url

# 4. 데이터 유출
HtmlJSScanner.exe "test/exfilterator.js" test_exfil

# 5. 실제 악성코드
HtmlJSScanner.exe "test/adam/final_page.html.txt" test_adam
```

### 예상 출력

```
HtmlJSScanner (C++) starting
Analysis finished in 342 ms

[CRITICAL] clipboard_hijacking (Severity: 10)
[HIGH] malicious_command (Severity: 9)
[MEDIUM] script_injection (Severity: 7)

ATTACK CHAINS DETECTED: 2
TOTAL DETECTIONS: 5

Report saved to: scan_results/task_001_20250103.json
```

---

## 📈 성능

| 파일 크기 | 분석 시간 | 메모리 사용 |
|-----------|-----------|-------------|
| 10KB (일반 JS) | ~100-300ms | 80MB |
| 50KB (난독화) | ~500-1000ms | 100MB |
| 100KB+ (대용량) | ~1-3초 | 130MB |

---

## 🔐 보안

### 샌드박스 보호

- ✅ QuickJS 격리 환경 (실제 시스템 접근 불가)
- ✅ 네트워크 차단 (모킹만 가능)
- ✅ Timeout 보호 (무한 루프 방지)
- ✅ 메모리 제한 (메모리 폭탄 방지)

---

## 🛠️ 기술 스택

- **언어**: C++ (C++11+)
- **JS 엔진**: [QuickJS](https://bellard.org/quickjs/)
- **JSON**: [nlohmann/json](https://github.com/nlohmann/json)
- **빌드**: CMake, Visual Studio (MSBuild)

---

## 🔮 로드맵

### Phase 1: 성능 (Q1 2025)
- [ ] 멀티스레드 분석
- [ ] 점진적 결과 스트리밍

### Phase 2: 탐지 강화 (Q2 2025)
- [ ] 머신러닝 기반 탐지
- [ ] YARA 룰 통합
- [ ] WebAssembly 지원

### Phase 3: 플랫폼 (Q3 2025)
- [ ] Linux 완전 지원
- [ ] REST API 서버
- [ ] Docker 이미지

### Phase 4: 엔터프라이즈 (Q4 2025)
- [ ] 중앙 관리 대시보드
- [ ] 실시간 위협 인텔리전스

---

## 🤝 기여

### 새로운 Hook 추가

1. `builtin/objects/` 에 새 객체 클래스 추가
2. `JSAnalyzer` 에서 객체 등록
3. `HookType.h` 에 Hook 타입 추가
4. 테스트 케이스 작성

### 새로운 탐지 패턴 추가

1. `core/StringDeobfuscator.cpp` 패턴 DB 수정
2. `core/DynamicStringTracker.cpp` 탐지 로직 추가
3. 테스트 및 문서 업데이트

---

## 📞 지원

- **버그 리포트**: [GitHub Issues](https://github.com/your-repo/issues)
- **기능 요청**: Feature Request 양식
- **보안 취약점**: security@example.com

---

## 📜 라이선스

MIT License - 자세한 내용은 [LICENSE](LICENSE) 참조

### 사용된 오픈소스

- **QuickJS**: MIT License
- **nlohmann/json**: MIT License

---

## 🏆 감사의 말

- QuickJS 개발팀
- nlohmann/json 커뮤니티
- OWASP 보안 커뮤니티
- VirusTotal & Hybrid Analysis

---

## 📖 참고 자료

### 기술 문서
- [QuickJS 공식 문서](https://bellard.org/quickjs/)
- [Taint Analysis](https://en.wikipedia.org/wiki/Taint_checking)
- [OWASP JavaScript Security](https://owasp.org/www-community/vulnerabilities/)

### 악성코드 분석
- [VirusTotal](https://www.virustotal.com/)
- [Any.Run](https://any.run/)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

**버전**: 1.0.0  
**마지막 업데이트**: 2025-01-03  
**개발팀**: Security Analysis Team

---

<div align="center">

**⭐ Star this project if you find it useful! ⭐**

[Documentation](docs/COMPREHENSIVE_PROJECT_REPORT.md) • 
[Architecture](docs/ARCHITECTURE_DIAGRAMS.md) • 
[Quick Start](docs/PROJECT_SUMMARY.md)

</div>
