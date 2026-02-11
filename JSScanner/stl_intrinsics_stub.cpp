// STL Intrinsics Stub Implementation
// This file provides missing intrinsic functions for compatibility with older toolsets

#include <cstddef>
#include <cstdint>

// Calling convention - Windows only
#ifdef _WIN32
#define STL_CALL __stdcall
#else
#define STL_CALL
#endif

// Disable precompiled headers for this file
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4100) // unreferenced formal parameter
#endif

// Only compile these functions on Windows (they're not needed on Linux)
#ifdef _WIN32

extern "C" {

// __std_find_last_of_trivial_pos_1 implementation
size_t STL_CALL __std_find_last_of_trivial_pos_1(
    const void* const _First1,
    const void* const _Last1,
    const void* const _First2,
    const void* const _Last2) noexcept
{
    const auto _Haystack_first = static_cast<const uint8_t*>(_First1);
    const auto _Haystack_last = static_cast<const uint8_t*>(_Last1);
    const auto _Needle_first = static_cast<const uint8_t*>(_First2);
    const auto _Needle_last = static_cast<const uint8_t*>(_Last2);
    
    const size_t _Haystack_size = _Haystack_last - _Haystack_first;
    
    for (size_t _Idx = _Haystack_size; _Idx > 0; --_Idx) {
        const auto _Ch = _Haystack_first[_Idx - 1];
        for (auto _Needle = _Needle_first; _Needle != _Needle_last; ++_Needle) {
            if (_Ch == *_Needle) {
                return _Idx - 1;
            }
        }
    }
    
    return static_cast<size_t>(-1); // Not found
}

// __std_find_first_of_trivial_pos_1 implementation
size_t STL_CALL __std_find_first_of_trivial_pos_1(
    const void* const _First1,
    const void* const _Last1,
    const void* const _First2,
    const void* const _Last2) noexcept
{
    const auto _Haystack_first = static_cast<const uint8_t*>(_First1);
    const auto _Haystack_last = static_cast<const uint8_t*>(_Last1);
    const auto _Needle_first = static_cast<const uint8_t*>(_First2);
    const auto _Needle_last = static_cast<const uint8_t*>(_Last2);
    
    const size_t _Haystack_size = _Haystack_last - _Haystack_first;
    
    for (size_t _Idx = 0; _Idx < _Haystack_size; ++_Idx) {
        const auto _Ch = _Haystack_first[_Idx];
        for (auto _Needle = _Needle_first; _Needle != _Needle_last; ++_Needle) {
            if (_Ch == *_Needle) {
                return _Idx;
            }
        }
    }
    
    return static_cast<size_t>(-1); // Not found
}

} // extern "C"

#endif // _WIN32

#ifdef _MSC_VER
#pragma warning(pop)
#endif
