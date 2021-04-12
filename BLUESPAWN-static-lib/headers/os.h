#pragma once

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
typedef unsigned long DWORD;
typedef unsigned __int64 DWORD64;
typedef void * PVOID64;
#endif