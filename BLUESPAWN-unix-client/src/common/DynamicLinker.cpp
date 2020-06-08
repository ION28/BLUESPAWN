#include "common/DynamicLinker.h"

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