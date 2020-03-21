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
	typedef std::function<bool(const AllocationWrapper&, const AllocationWrapper&)> REG_BINARY_CHECK;
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
		std::wstring name;
		
		RegistryType type;
		RegistryData value;
		std::variant<REG_SZ_CHECK, REG_DWORD_CHECK, REG_BINARY_CHECK, REG_MULTI_SZ_CHECK> check;

		bool MissingBad;
		
		RegistryCheck(std::wstring&& wValueName, std::wstring&& wData, bool MissingBad = false, const REG_SZ_CHECK& check = CheckSzEqual);
		RegistryCheck(std::wstring&& wValueName, DWORD&& dwData, bool MissingBad = false, const REG_DWORD_CHECK& check = CheckDwordEqual);
		RegistryCheck(std::wstring&& wValueName, AllocationWrapper&& lpData, bool MissingBad = false, const REG_BINARY_CHECK& check = CheckBinaryEqual);
		RegistryCheck(std::wstring&& wValueName, std::vector<std::wstring>&& wData, bool MissingBad = false,
			const REG_MULTI_SZ_CHECK& check = CheckMultiSzSubset);

		RegistryType GetType() const;

		bool operator()(const RegistryData& data) const;
	};

	/**
	 * Checks the values under a certain key using the RegistryCheck class. if CheckWow64 is true, this will attempt to automatically redirect to the WoW64 version
	 * of the key in addition to the 64-bit one. If CheckUsers is true, this will attempt to automatically check the same key under each user in addition to under
	 * HKLM. 
	 *
	 * @param hkHive The registry hive under which the path lies. 
	 * @param path The path to the specified key under the given hive. If CheckUsers is true, this will will also check the path under each user's account.
	 * @param CheckWow64 If true, this will also check the wow64 version of the key, if one exists
	 * @param CheckUsers If true, this will check for the path under all users' hives in addition to the given one
	 *
	 * @return A vector containing a RegistryValue object for each RegistryCheck that didn't match its valid conditions
	 */
	std::vector<RegistryValue> CheckValues(const HKEY& hkHive, const std::wstring& path, const std::vector<RegistryCheck>& values, bool CheckWow64 = true, bool CheckUsers = true);

	/**
	 * Checks for any values under a certain key. if CheckWow64 is true, this will attempt to automatically redirect to the WoW64 version of the key
	 * in addition to the 64-bit one. If CheckUsers is true, this will attempt to automatically check the same key under each user in addition to under
	 * HKLM.
	 *
	 * @param hkHive The registry hive under which the path lies.
	 * @param path The path to the specified key under the given hive. If CheckUsers is true, this will will also check the path under each user's account.
	 * @param CheckWow64 If true, this will also check the wow64 version of the key, if one exists
	 * @param CheckUsers If true, this will check for the path under all users' hives in addition to the given one
	 *
	 * @return A vector containing a RegistryValue object for each RegistryCheck that didn't match its valid conditions
	 */
	std::vector<RegistryValue> CheckKeyValues(const HKEY& hkHive, const std::wstring& path, bool CheckWow64 = true, bool CheckUsers = true);

	/**
	 * Checks for any values under a certain key. if CheckWow64 is true, this will attempt to automatically redirect to the WoW64 version of the key
	 * in addition to the 64-bit one. If CheckUsers is true, this will attempt to automatically check the same key under each user in addition to under
	 * HKLM.
	 *
	 * @param hkHive The registry hive under which the path lies.
	 * @param path The path to the specified key under the given hive. If CheckUsers is true, this will will also check the path under each user's account.
	 * @param CheckWow64 If true, this will also check the wow64 version of the key, if one exists
	 * @param CheckUsers If true, this will check for the path under all users' hives in addition to the given one
	 *
	 * @return A vector containing a RegistryValue object for each RegistryCheck that didn't match its valid conditions
	 */
	std::vector<RegistryKey> CheckSubkeys(const HKEY& hkHive, const std::wstring& path, bool CheckWow64 = true, bool CheckUsers = true);
}