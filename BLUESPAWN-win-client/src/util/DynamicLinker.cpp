#include "util/DynamicLinker.h"

#include <Windows.h>
#include <winternl.h>

#include <vector>
#include <functional>
#include <iostream>

namespace Linker {
	std::vector<std::function<bool()>> LoadCalls = {};

	bool LinkFunctions(){
		for(auto func : LoadCalls){
			if(!func()){
				return false;
			}
		}
		return true;
	}
}