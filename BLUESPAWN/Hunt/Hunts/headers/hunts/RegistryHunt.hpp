#pragma once
#include "configuration/Registry.h"
#include "reactions/Reaction.h"

#include <algorithm>

namespace Registry {
	enum MatchAction {
		MATCH_BAD,
		NO_MATCH_BAD
	};

	template<class T>
	inline bool CheckKey(RegistryKey key, T value, Reaction* reaction, MatchAction bOnMatch = NO_MATCH_BAD){
		bool equal = key.Get<T>() == value;

		if(!equal && bOnMatch == NO_MATCH_BAD || equal && bOnMatch == MATCH_BAD){
			LOG_WARNING("Potentially bad registry key " << key << " with value \"" << key.Get<T>() << "\". Value should " << (bOnMatch == NO_MATCH_BAD ? "" : "not ") << "be \"" << value << "\"");

			reaction->RegistryKeyIdentified(key);
		} else {
			LOG_VERBOSE(1, "Registry key value " << key << " is okay");
		}

		return equal;
	}

	template<>
	inline bool CheckKey(RegistryKey key, LPCWSTR value, Reaction* reaction, MatchAction bOnMatch){
		return CheckKey(key, std::wstring(value), reaction, bOnMatch);
	}

	template<>
	inline bool CheckKey(RegistryKey key, REG_MULTI_SZ_T values, Reaction* reaction, MatchAction bOnMatch){
		bool good = true;

		for(auto value : key.Get<REG_MULTI_SZ_T>()){
			bool inList = find(values.begin(), values.end(), value) != values.end();
			if(inList && bOnMatch == MATCH_BAD || !inList && bOnMatch == NO_MATCH_BAD) {
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

	inline int CheckForSubkeys(RegistryKey key, Reaction* reaction){
		int IDd = 0;
		for(auto subkey : key.Subkeys()){
			IDd++;
			reaction->RegistryKeyIdentified(subkey);
		}

		return IDd;
	}

	inline int CheckForValues(RegistryKey key, Reaction* reaction){
		int IDd = 0;
		for(auto subkey : key.KeyValues()){
			IDd++;
			reaction->RegistryKeyIdentified(subkey);
		}

		return IDd;
	}
}