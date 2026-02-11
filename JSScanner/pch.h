#pragma once
#define _CRT_SECURE_NO_WARNINGS

// Windows headers FIRST (before any other headers)
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#endif

// Standard Library (AFTER Windows headers)
#include <vector>
#include <list>
#include <stack>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <iostream>
#include <optional>
#include <chrono>
#include <random>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <memory>
#include <mutex>
#include <atomic>
#include <re2/re2.h>
#include <variant>
#include <functional>
#include <future>
#include <cstdio>

#if defined(_WIN32) || defined(__CYGWIN__)
#ifdef JSScanner_EXPORTS
#define JSScanner_API __declspec(dllexport)
#else
#define JSScanner_API __declspec(dllimport)
#endif
#elif __GNUC__ >= 4 || defined(__clang__)
#define JSScanner_API __attribute__((visibility("default")))
#else
#define JSScanner_API
#endif

#include "../../../../cppcore/Inc/cppcore.h"

using namespace core;

#include "../../../../mon47-opensrc/opensrc/quickjs-ng/include/quickjs.h"
#include "../../../../mon47-opensrc/opensrc/gumbo/include/gumbo.h"
#define CURL_STATICLIB
#include "../../../../mon47-opensrc/opensrc/curl-impersonate/include/curl/curl.h"

// JSON library 
#include "../../Getter/Resolver/ExternalLib_json.hpp"

#include "model/Detection.h"

// Common
#include "../Common/CurlInit.hpp"

// Global log prefix
extern std::string logMsg;
