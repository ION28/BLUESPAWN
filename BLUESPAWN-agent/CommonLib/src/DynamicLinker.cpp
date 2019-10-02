#include "common/DynamicLinker.h"

#include <Windows.h>
#include <winternl.h>

#include <vector>
#include <functional>

#define LINK_FUNCTION(name, dll)                                                            \
    name##_type name##;                                                                     \
    auto res_##name = LoadCalls.emplace_back(std::bind([](name##_type* param){              \
        *param = reinterpret_cast<name##_type>(GetProcAddress(LoadLibraryW(L#dll), #name)); \
		return *param == nullptr;                                                           \
    }, &name))

namespace Linker {
	std::vector<std::function<bool()>> LoadCalls = {};

	LINK_FUNCTION(LdrpPreprocessDllName, NTDLL.dll);

	bool LoadFunctions(){
		for(auto func : LoadCalls){
			if(!func()){
				return false;
			}
		}
		return true;
	}
}