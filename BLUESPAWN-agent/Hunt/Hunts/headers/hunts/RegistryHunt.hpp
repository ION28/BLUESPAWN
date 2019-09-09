#pragma once
#include "configuration/Registry.h"
#include "reactions/Reaction.h"

#include <algorithm>

/**
 * Forward facing API for checking registry key values against known good or known bad values.
 *
 * All hunts that check registry values should interract with functions here rather than the RegistryKey class
 * when possible, and if functionality is needed that can't be provided from one of the functions here, it should
 * be implemented here. This is so that the RegistryKey class can change without destroying hunts.
 */

namespace Registry {
	enum MatchAction {
		MATCH_BAD,
		NO_MATCH_BAD
	};

	/**
	 * The standard registry key check. This checks a given registry key against a given value. If the MatchAction is set to
	 * MATCH_BAD and the key's value matches the given value, the reaction is triggered. If the MatchAction is set to NO_MATCH_BAD
	 * and the key's value does not match the given value, the reaction is triggered. 
	 *
	 * @param key The registry key object to check
	 * @param value The value to check the registry key's value against
	 * @param reaction The reaction to trigger if it is determined the registry key's value is bad
	 * @param bOnMatch An enum indicating whether or not the key's value should match the given value
	 *
	 * @return True if a detection occured and a reaction was dispatched; false otherwise
	 */
	template<class T>
	inline bool CheckKey(RegistryKey key, T value, Reaction* reaction, MatchAction bOnMatch = NO_MATCH_BAD){
		bool equal = key.Get<T>() == value;

		if(!equal && bOnMatch == NO_MATCH_BAD || equal && bOnMatch == MATCH_BAD){
			LOG_WARNING("Potentially bad registry key " << key << " with value \"" << key.Get<T>() << "\". Value should " << (bOnMatch == NO_MATCH_BAD ? "" : "not ") << "be \"" << value << "\"");

			REGISTRY_DETECTION detection{ key.GetPath(), key.GetName(), reinterpret_cast<BYTE*>(key.GetRaw()) };
			reaction->RegistryKeyIdentified(&detection);

			return true;
		} else {
			LOG_VERBOSE(1, "Registry key value " << key << " is okay");

			return false;
		}
	}

	/**
	 * The standard registry key check. This checks a given registry key against a list of values. If the MatchAction is set to
	 * MATCH_BAD and the key's value matches any given value, the reaction is triggered. If the MatchAction is set to NO_MATCH_BAD
	 * and the key's value does not match any given value, the reaction is triggered.
	 *
	 * @param key The registry key object to check
	 * @param value The values to check the registry key's value against
	 * @param reaction The reaction to trigger if it is determined the registry key's value is bad
	 * @param bOnMatch An enum indicating whether or not the key's value should match a given value
	 *
	 * @return True if a detection occured and a reaction was dispatched; false otherwise
	 */
	template<class T>
	inline bool CheckKey(RegistryKey key, std::vector<T> values, Reaction* reaction, MatchAction bOnMatch = NO_MATCH_BAD){
		T KeyValue = key.Get<T>();
		bool matched = false;
		for(auto value : values){
			bool equal = KeyValue == value;

			if(equal && bOnMatch == MATCH_BAD){
				LOG_WARNING("Potentially bad registry key " << key << " with value \"" << KeyValue << "\". Value should not be \"" << value << "\"");

				REGISTRY_DETECTION detection{ key.GetPath(), key.GetName(), reinterpret_cast<BYTE*>(key.GetRaw()) };
				reaction->RegistryKeyIdentified(&detection);

				return true;
			} else if(equal && bOnMatch == NO_MATCH_BAD){
				matched = true;
			}
		}
		if(bOnMatch == NO_MATCH_BAD && matched){
			LOG_VERBOSE(1, "Registry key value " << key << " is okay");

			return false;
		} else if(bOnMatch == NO_MATCH_BAD && !matched){
			std::stringstream stream;
			stream << "\"" << values[0];
			for(int i = 1; i < values.size(); i++){
				stream << " or \"" << values[i] << "\"";
			}

			LOG_WARNING("Potentially bad registry key " << key << " with value \"" << key.Get<T>() << "\". Value should " << (bOnMatch == NO_MATCH_BAD ? "" : "not ") << "be " << stream << "");
		}

		return !matched && bOnMatch == NO_MATCH_BAD;
	}

	/// A specialization of CheckKey in the case that the value is a C wide-string
	template<>
	inline bool CheckKey(RegistryKey key, LPCWSTR value, Reaction* reaction, MatchAction bOnMatch){
		return CheckKey(key, std::wstring(value), reaction, bOnMatch);
	}

	/**
	 * A specialization of CheckKey in the case that the value is a string array. This handles cases where the registry key
	 * is a MULTI_SZ by checking all of the key's values against all of the given values. If the key is just a single string,
	 * then the same logic is applied to just the one value, acting like the CheckKey function normally does when given a vector.
	 */
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
			REGISTRY_DETECTION detection{ key.GetPath(), key.GetName(), reinterpret_cast<BYTE*>(key.GetRaw()) };
			reaction->RegistryKeyIdentified(&detection);

		} else {
			LOG_VERBOSE(1, "Registry key value " << key << " is okay");
		}

		return good;
	}

	/**
	 * Checks if a registry key has any subkeys.
	 *
	 * @param key The registry key to check for subkeys
	 * @param reaction The reaction to trigger for each subkey
	 *
	 * @return The number of subkeys present
	 */
	inline int CheckForSubkeys(RegistryKey key, Reaction* reaction){
		int IDd = 0;
		for(auto subkey : key.Subkeys()){
			IDd++;
			REGISTRY_DETECTION detection{ subkey.GetPath(), subkey.GetName(), reinterpret_cast<BYTE*>(subkey.GetRaw()) };
			reaction->RegistryKeyIdentified(&detection);
		}

		return IDd;
	}


	/**
	 * Checks if a registry key has any values.
	 *
	 * @param key The registry key to check for values
	 * @param reaction The reaction to trigger for each values
	 *
	 * @return The number of values present
	 */
	inline int CheckForValues(RegistryKey key, Reaction* reaction){
		int IDd = 0;
		for(auto subkey : key.KeyValues()){
			IDd++;
			REGISTRY_DETECTION detection{ subkey.GetPath(), subkey.GetName(), reinterpret_cast<BYTE*>(subkey.GetRaw()) };
			reaction->RegistryKeyIdentified(&detection);
		}

		return IDd;
	}
}