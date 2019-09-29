#include "common/DynamicLinker.h"

#include <Windows.h>
#include <winternl.h>

#include <vector>

#define LINK_FUNCTION(name, dll) \
    name##_type name##_func = reinterpret_cast<name##_type>(GetProcAddress(LoadLibraryW(L#dll), #name));

std::vector<bool(*)()> LoadCalls = {};

LINK_FUNCTION(LdrpPreprocessDllName, NTDLL);

bool LoadFunctions(){
	for(auto func : LoadCalls){
		if(!func()){
			return false;
		}
	}
	return true;
}