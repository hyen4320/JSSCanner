// 미구현 브라우저 API 테스트
// ProxyFallbackObject가 정상 작동하는지 확인

console.log("=== 미구현 API 테스트 시작 ===");

// 1. 존재하지 않는 전역 객체 접근
try {
    var result1 = undefinedGlobalAPI;
    console.log("undefinedGlobalAPI 접근 성공:", typeof result1);
} catch (e) {
    console.log("ERROR: undefinedGlobalAPI 접근 실패:", e.message);
}

// 2. 존재하지 않는 함수 호출
try {
    var result2 = nonExistentFunction();
    console.log("nonExistentFunction() 호출 성공:", typeof result2);
} catch (e) {
    console.log("ERROR: nonExistentFunction() 호출 실패:", e.message);
}

// 3. window의 미구현 속성 접근
try {
    var result3 = window.notImplementedProperty;
    console.log("window.notImplementedProperty 접근 성공:", typeof result3);
} catch (e) {
    console.log("ERROR: window.notImplementedProperty 접근 실패:", e.message);
}

// 4. navigator의 미구현 메서드 호출
try {
    var result4 = navigator.notImplementedMethod();
    console.log("navigator.notImplementedMethod() 호출 성공:", typeof result4);
} catch (e) {
    console.log("ERROR: navigator.notImplementedMethod() 호출 실패:", e.message);
}

// 5. 구현된 API는 정상 작동하는지 확인
try {
    console.log("console.log 정상 작동");
    var encoded = btoa("test");
    console.log("btoa 정상 작동:", encoded);
    var decoded = atob(encoded);
    console.log("atob 정상 작동:", decoded);
} catch (e) {
    console.log("ERROR: 구현된 API 실패:", e.message);
}

// 6. 복잡한 체이닝 테스트
try {
    var result6 = window.crypto.subtle.encrypt({name: "AES-GCM"}, null, null);
    console.log("window.crypto.subtle.encrypt 체이닝 성공:", typeof result6);
} catch (e) {
    console.log("ERROR: crypto 체이닝 실패:", e.message);
}

// 7. 존재하지 않는 객체에 값 설정
try {
    someUndefinedObject = {test: "value"};
    console.log("존재하지 않는 객체에 값 설정 성공:", someUndefinedObject.test);
} catch (e) {
    console.log("ERROR: 값 설정 실패:", e.message);
}

console.log("=== 미구현 API 테스트 완료 ===");
