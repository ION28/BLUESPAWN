#pragma once
#include "configuration/Registry.h"
#include "reactions/Reaction.h"

namespace Registry {
	template<class T>
	inline bool CheckKey(RegistryKey key, T value, Reaction* reaction){
		bool equal = key.Get<T>() == value;

		if(!equal){
			LOG_WARNING("Potentially bad registry key " << key << " with value " << key.Get<T>());

			reaction->RegistryKeyIdentified(key);
		}
	}
}