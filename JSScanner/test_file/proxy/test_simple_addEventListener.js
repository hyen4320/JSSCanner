// ProxyFallback 설치 확인 테스트
console.log("Test 1: window.addEventListener 존재하는지 확인");
console.log("typeof window.addEventListener =", typeof window.addEventListener);

console.log("Test 2: document.addEventListener 존재하는지 확인");
console.log("typeof document.addEventListener =", typeof document.addEventListener);

console.log("Test 3: window.addEventListener 호출");
window.addEventListener('load', function() {
    console.log('Load event fired!');
});

console.log("=== 테스트 완료 ===");
