#pragma once

#include <Windows.h>
#include <winternl.h>

#include <vector>
#include <functional>

#define DEFINE_FUNCTION(retval, name, convention, ...)    \
    typedef retval(convention *name##_type)(__VA_ARGS__); \
    namespace Linker { extern name##_type name##; }

#define LINK_FUNCTION(name, dll)                                                                        \
    namespace Linker {                                                                                  \
        name##_type name## = reinterpret_cast<name##_type>(GetProcAddress(LoadLibraryW(L#dll), #name)); \
    }