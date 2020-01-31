#pragma once
#include "util/configurations/Registry.h"
#include "util/configurations/RegistryValue.h"
#include "HuntInfo.h"

#include <vector>
#include <functional>
#include <string>

/**
 * Forward facing API for checking registry key values against known good or known bad values.
 *
 * All hunts that check registry values should interact with functions here rather than the RegistryKey class
 * when possible, and if functionality is needed that can't be provided from one of the functions here, it should
 * be implemented here. This is so that the RegistryKey class can change without destroying hunts.
 */

namespace Registry {

	typedef std::function<bool(const std::wstring&, const std::wstring&)> REG_SZ_CHECK;
	typedef std::function<bool(DWORD, DWORD)> REG_DWORD_CHECK;
	typedef std::function<bool(LPVOID, LPVOID)> REG_BINARY_CHECK;
	typedef std::function<bool(const std::vector<std::wstring>&, const std::vector<std::wstring>&)> REG_MULTI_SZ_CHECK;

	extern REG_SZ_CHECK CheckSzEqual;
	extern REG_SZ_CHECK CheckSzRegexMatch;
	extern REG_SZ_CHECK CheckSzNotEqual;
	extern REG_SZ_CHECK CheckSzRegexNotMatch;
	extern REG_SZ_CHECK CheckSzEmpty;

	extern REG_DWORD_CHECK CheckDwordEqual;
	extern REG_DWORD_CHECK CheckDwordNotEqual;

	extern REG_BINARY_CHECK CheckBinaryEqual;
	extern REG_BINARY_CHECK CheckBinaryNotEqual;
	extern REG_BINARY_CHECK CheckBinaryNull;

	extern REG_MULTI_SZ_CHECK CheckMultiSzSubset;
	extern REG_MULTI_SZ_CHECK CheckMultiSzExclusion;
	extern REG_MULTI_SZ_CHECK CheckMultiSzEmpty;

	/**
	 * A container class for registry values and associated data.
	 */
	struct RegistryCheck {
		RegistryValue value;
		bool MissingBad;

		REG_SZ_CHECK wCheck;
		REG_DWORD_CHECK dwCheck;
		REG_BINARY_CHECK lpCheck;
		REG_MULTI_SZ_CHECK vCheck;
		
		RegistryCheck(std::wstring wValueName, RegistryType type, std::wstring wData, bool MissingBad = false,
			REG_SZ_CHECK check = CheckSzEqual);
		RegistryCheck(std::wstring wValueName, RegistryType type, DWORD dwData, bool MissingBad = false,
			REG_DWORD_CHECK check = CheckDwordEqual);
		RegistryCheck(std::wstring wValueName, RegistryType type, MemoryWrapper<> lpData, bool MissingBad = false,
			REG_BINARY_CHECK check = CheckBinaryEqual);
		RegistryCheck(std::wstring wValueName, RegistryType type, std::vector<std::wstring> wData, bool MissingBad = false,
			REG_MULTI_SZ_CHECK check = CheckMultiSzSubset);

		RegistryCheck(const RegistryCheck& copy);
		RegistryCheck operator=(const RegistryCheck& copy);

		~RegistryCheck();

		RegistryType GetType() const;
	};

	std::vector<RegistryValue> CheckValues(const RegistryKey& key, const std::vector<RegistryCheck> values);

	std::vector<RegistryValue> CheckKeyValues(const RegistryKey& key);

	std::vector<RegistryKey> CheckSubkeys(const RegistryKey& key);
}