#pragma once

#include <Windows.h>
#include <winternl.h>

#include <vector>
#include <functional>

#define DEFINE_FUNCTION(retval, name, convention, ...)    \
    typedef retval(convention *name##_type)(__VA_ARGS__); \
    namespace Linker { extern name##_type name##; }

#define LINK_FUNCTION(name, dll)                                                                \
    namespace Linker {                                                                          \
        name##_type name##;                                                                     \
        auto res_##name = LoadCalls.emplace_back(std::bind([](name##_type* param){              \
            *param = reinterpret_cast<name##_type>(GetProcAddress(LoadLibraryW(L#dll), #name)); \
		    return *param == nullptr;                                                           \
        }, &name));                                                                             \
    }

namespace Linker {
	extern std::vector<std::function<bool()>> LoadCalls;
	bool LinkFunctions();
}