#include <string>
#include <iostream>

#include "reaction/RemoveValue.h"
#include "util/configurations/Registry.h"
#include "common/wrappers.hpp"

#include "util/log/Log.h"

namespace Reactions{

	void RemoveValueReaction::RemoveRegistryIdentified(std::shared_ptr<REGISTRY_DETECTION> detection){
		if(io.GetUserConfirm(L"Registry key " + detection->value.key.ToString() + L" contains potentially malicious value "
			+ detection->value.wValueName + L" with data " + detection->value.ToString() + L". Remove value?") == 1){
			if(!detection->value.key.RemoveValue(detection->value.wValueName)){
				LOG_ERROR("Unable to remove registry value " << detection->value.key.ToString() << ": " << detection->value.wValueName << " (Error " << GetLastError() << ")");
			}
		}
	}

	RemoveValueReaction::RemoveValueReaction(const IOBase& io) : io{ io }{
		vRegistryReactions.emplace_back(std::bind(&RemoveValueReaction::RemoveRegistryIdentified, this, std::placeholders::_1));
	}
}