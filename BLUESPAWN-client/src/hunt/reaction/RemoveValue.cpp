#include <string>
#include <iostream>

#include "hunt/reaction/RemoveValue.h"
#include "util/configurations/Registry.h"
#include "common/wrappers.hpp"

#include "util/log/Log.h"

namespace Reactions{

	void RemoveValueReaction::RemoveRegistryIdentified(std::shared_ptr<REGISTRY_DETECTION> detection){
		if(io.GetUserConfirm(L"Registry key " + detection->wsRegistryKeyPath + L" contains potentially malicious value "
			+ detection->contents.wValueName + L" with data " + detection->contents.ToString() + L". Remove value?") == 1){
			auto key = Registry::RegistryKey{ detection->wsRegistryKeyPath };
			if(!key.RemoveValue(detection->contents.wValueName)){
				LOG_ERROR("Unable to remove registry value " << detection->wsRegistryKeyPath << ": " << detection->contents.wValueName << " (Error " << GetLastError() << ")");
			}
		}
	}

	RemoveValueReaction::RemoveValueReaction(const IOBase& io) : io{ io }{
		vRegistryReactions.emplace_back(std::bind(&RemoveValueReaction::RemoveRegistryIdentified, this, std::placeholders::_1));
	}
}