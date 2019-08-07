#pragma once
#include "configuration/Registry.h"
#include "reactions/Reaction.h"

namespace Registry {
	constexpr bool MATCH_BAD = false;
	constexpr bool NO_MATCH_BAD = true;

	template<class T>
	inline bool CheckKey(RegistryKey key, T value, Reaction* reaction, bool bOnMatch = NO_MATCH_BAD){
		bool equal = key.Get<T>() == value;

		if(!equal && bOnMatch || equal && !bOnMatch){
			LOG_WARNING("Potentially bad registry key " << key << " with value " << key.Get<T>());

			reaction->RegistryKeyIdentified(key);
		} else {
			LOG_VERBOSE(1, "Registry key value " << key << " is okay");
		}

		return equal;
	}

	/**
	 * Returns true if the values contained in the given registry are a proper subset of those in the
	 * given value
	 */
	template<>
	inline bool CheckKey(RegistryKey key, REG_MULTI_SZ_T values, Reaction* reaction, bool bOnMatch){
		bool good = true;

		for(auto value : key.Get<REG_MULTI_SZ_T>()){
			if(find(values.begin(), values.end(), value) == values.end()) {
				LOG(Log::_LogCurrentSinks, Log::LogLevel::LogWarn, "Potentially malicious registry key value discovered - " << value << Log::endlog
					<< "Registry key is " << key << Log::endlog);
				good = false;
			}
		}
		
		if(!good){
			reaction->RegistryKeyIdentified(key);
		} else {
			LOG_VERBOSE(1, "Registry key value " << key << " is okay");
		}

		return good;
	}
}