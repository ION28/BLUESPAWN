#pragma once
#include <string>
#include <cstdint>

#if defined(_WIN32) || defined(_WIN64)
#define BLUESPAWN_WINDOWS
#elif defined(__linux__)
#define BLUESPAWN_LINUX
#elif defined (__FreeBSD__)
#define BLUESPAWN_BSD
#else
#error "Cannot determine operating system"
#endif

#if defined(BLUESPAWN_LINUX) || defined(BLUESPAWN_BSD)
typedef uint32_t DWORD;
typedef uint64_t DWORD64;
typedef void * PVOID64;
typedef std::string bstring;
#define IN
#else
typedef std::wstring bstring;
#endif