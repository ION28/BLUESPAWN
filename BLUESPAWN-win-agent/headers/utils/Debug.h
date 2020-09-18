#pragma once

#include <windows.h>

#include <sstream>

#define LOG_INFO "INFO"
#define LOG_WARN "WARN"
#define LOG_ERROR "ERROR"

#ifdef _DEBUG

// https://stackoverflow.com/a/54335644/4815264
template <typename T, size_t S>
inline constexpr size_t get_file_name_offset(const T(&str)[S], size_t i = S - 1){
    return (str[i] == '/' || str[i] == '\\') ? i + 1 : (i > 0 ? get_file_name_offset(str, i - 1) : 0);
}

template <typename T>
inline constexpr size_t get_file_name_offset(T(&str)[1]){
    return 0;
}

namespace utility{
    template <typename T, T v>
    struct const_expr_value {
        static constexpr const T value = v;
    };
}
#define UTILITY_CONST_EXPR_VALUE(exp) ::utility::const_expr_value<decltype(exp), exp>::value

namespace BLUESPAWN::Agent::Log {
    extern std::wstring name;
};

#define DEBUG_STREAM(...) \
    OutputDebugStringW((std::wstringstream{} << __VA_ARGS__).str().c_str())

#define LOG_DEBUG_MESSAGE(type, ...)                                                                      \
     DEBUG_STREAM(L"[BLUESPAWN Agent][" << BLUESPAWN::Agent::Log::name << "][" type "]["                  \
                       << &__FILE__[UTILITY_CONST_EXPR_VALUE(get_file_name_offset(__FILE__))] << " line " \
                       << __LINE__ << L"] " << __VA_ARGS__)
#else
#define LOG_DEBUG_MESSAGE(...)
#define DEBUG_STREAM(...)
#endif
