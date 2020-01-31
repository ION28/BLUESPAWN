#pragma once

#include <Windows.h>

#include <string>
#include <vector>
#include <map>
#include <optional>

#include "common/DynamicLinker.h"
#include "common/wrappers.hpp"

#include "util/log/Loggable.h"
#include "util/configurations/RegistryValue.h"

DEFINE_FUNCTION(DWORD, NtQueryKey, __stdcall, HANDLE KeyHandle, int KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);

namespace Registry {
	extern std::map<std::wstring, HKEY> vHiveNames;
	extern std::map<HKEY, std::wstring> vHives;

	/**
	 * This class is for interaction with the Windows Registry. A single instance of this
	 * class represents a key in the registry, not to be confused with a value. Note that each
	 * key will have multiple values in addition to some number of subkeys. Each value is associated
	 * with data, which will generally be a REG_DWORD, REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, or 
	 * REG_BINARY. This class provides support for all of these. 
	 */
	class RegistryKey : 
		public Loggable {
	public:
		/* Copy constructor for a RegistryKey */
		RegistryKey(const RegistryKey& key) noexcept;

		/* Move constructor for a RegistryKey */
		RegistryKey(RegistryKey&& key) noexcept;

		/**
		 * Creates a RegistryKey object from the backing associated HKEY.
		 *
		 * @param key The HKEY handle on the registry key to create an instance for.
		 */
		RegistryKey(HKEY key);

		/**
		 * Creates a RegistryKey object from a path relative to a given HKEY.
		 * For example, the HKEY may reference the key at HKLM\SYSTEM and the path may be 
		 * CurrentControlSet\Services. The resulting instance would reference the key stored at
		 * HKLM\SYSTEM\CurrentControlSet\Services.
		 *
		 * @param base The base key.
		 * @param path The path relative to the base key.
		 */
		RegistryKey(HKEY base, std::wstring path);

		/**
		 * Creates a RegistryKey object to reference a key at a given path.
		 *
		 * @param path The path of the registry key to reference.
		 */
		RegistryKey(std::wstring path);

		/** Copy operator overload */
		RegistryKey& operator=(const RegistryKey& key) noexcept;

		/** Move operator overload */
		RegistryKey& operator=(RegistryKey&& key) noexcept;

	private:
		static std::map<HKEY, int> _ReferenceCounts;

		HKEY hkBackingKey;

		bool bKeyExists;

		HKEY hkHive{};
		std::wstring path{};

	public:
		/** Destructor for a RegistryKey. Decrements a reference count, and if zero, closes the handle */
		~RegistryKey();

		/** 
		 * Indicates whether this instance references a registry key that exists.
		 *
		 * @return true if the referenced key exists; false otherwise
		 */
		bool Exists() const;

		/**
		 * Indicates whether the referenced key contains a certain value.
		 *
		 * @param wsValueName The name of the value to check.
		 *
		 * @return true if the referenced key has the given value; false otherwise
		 */
		bool ValueExists(std::wstring wsValueName) const;

		/**
		 * If the registry key referenced by this instance doesn't exist, this will create it.
		 * 
		 * @return true if the registry key already existed or was created; false otherwise.
		 */
		bool Create();

		/**
		 * Reads the raw bytes present in a given value. 
		 *
		 * @return A AllocationWrapper object pointing to the bytes read if the value is present, or
		 *	       an empty memory wrapper if the value is not present. The memory must be freed.
		 */
		AllocationWrapper GetRawValue(std::wstring wsValueName) const;

		/**
		 * Writes bytes to a given value under the key referenced by this object.
		 *
		 * @param name The name of the value to set
		 * @param bytes The bytes to write to the value
		 * @param type The datatype of the value
		 *
		 * @return True if the value was successfully set; false otherwise
		 */
		bool SetRawValue(std::wstring name, AllocationWrapper bytes, DWORD type = REG_BINARY) const;

		/**
		 * Reads data from the specified value and handles conversion to common types.
		 * Supported types: std::wstring (REG_SZ and REG_EXPAND_SZ), std::vector<std::wstring>
		 * (REG_MULTI_SZ), and DWORD (REG_DWORD). 
		 * In other types, the data stored in the value will be converted to the template type.
		 *
		 * @param wsValueName The name of the value to read.
		 *
		 * @return An optional containing the object stored in the registry, or nullopt if an error
		 *		   occured or the value does exist.
		 */
		template<class T>
		std::optional<T> GetValue(std::wstring wsValueName) const;

		/**
		 * Returns the type of a value under the currently referenced registry key.
		 * Currently, this only supports REG_SZ, REG_EXPAND_SZ, REG_DWORD, and REG_MULTI_SZ.
		 *
		 * @param wsValueName The name of the value to check
		 *
		 * @return An optional containing the registry type, or nullopt if the value does not exist or
		 *		   an error ocurred.
		 */
		std::optional<RegistryType> GetValueType(std::wstring wsValueName) const;

		/**
		 * Sets data for a specified value under the referenced key and handles conversions from
		 * common types. For common types, the size and type do not need to be specified.
		 * Supported types: std::wstring, std::string, LPCSTR, LPCWSTR, DWORD, and 
		 * std::vector<std::wstring>.
		 *
		 * @param name The name of the value to set.
		 * @param value The data to write to the value.
		 * @param size The size of the data to write. This is ignored if the type is one of the
		 *        supported types for this function.
		 * @param type The registry datatype for the data to write. This is ignored if the type is
		 *	      one of the supported types for this function.
		 *
		 * @return True if the value was successfully set; false otherwise.
		 */
		template<class T>
		bool SetValue(std::wstring name, T value, DWORD size = sizeof(T), DWORD type = REG_BINARY) const;

		/**
		 * Returns a list of values present under the currently referenced registry key.
		 *
		 * @return a list of values present under the currently referenced registry key.
		 */
		std::vector<std::wstring> EnumerateValues() const;

		/**
		 * Returns a list of subkeys under the currently referenced registry key.
		 *
		 * @return a list of subkeys under the currently referenced registry key.
		 */
		std::vector<RegistryKey> EnumerateSubkeys() const;

		/**
		 * Returns the full path of the referenced registry key.
		 *
		 * @return the full path of the referenced registry key.
		 */
		std::wstring GetName() const;

		virtual std::wstring ToString() const;
		bool operator<(RegistryKey key) const;
	};
}