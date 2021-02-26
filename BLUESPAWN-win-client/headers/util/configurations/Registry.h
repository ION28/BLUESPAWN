#pragma once

#include <Windows.h>

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <variant>
#include <type_traits>

#include "util/DynamicLinker.h"
#include "util/wrappers.hpp"

#include "util/log/Loggable.h"

DEFINE_FUNCTION(DWORD, NtQueryKey, NTAPI, HANDLE KeyHandle, int KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
DEFINE_FUNCTION(NTSTATUS, NtQueryValueKey, NTAPI, HANDLE KeyHandle, PUNICODE_STRING ValueName, int KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
DEFINE_FUNCTION(NTSTATUS, NtDeleteValueKey, NTAPI, HANDLE KeyHandle, PUNICODE_STRING ValueName);

#define DEFAULT L""

/**
 * This enum represents the datatypes stored in the registry.
 * While other types do exist, for now, support only exists for the below types.
 */
enum class RegistryType {
	REG_SZ_T,
	REG_EXPAND_SZ_T,
	REG_MULTI_SZ_T,
	REG_DWORD_T,
	REG_BINARY_T
};

namespace Registry {

	typedef std::variant<std::wstring, DWORD, AllocationWrapper, std::vector<std::wstring>> RegistryData;

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

		/**
		 * Checks if a given registry key exists.
		 *
		 * @param hive The registry hive to search for `name`
		 * @param name The path to the registry key under `hive`
		 * @param WoW64 True if the key should be reflected/redirected for WoW64; false otherwise.
		 *
		 * @return true if the key exists; false otherwise
		 */
		static bool CheckKeyExists(HKEY hive, const std::wstring& name, bool WoW64 = false);

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
		 * @param WoW64 Indicate whether this instance should refer to the WoW64 version of a key. For keys without 
		 *        WoW64 versions, this has no effect. If Wow6432node is part of the provided path, this value is ignored.
		 */
		RegistryKey(HKEY base, std::wstring path, bool WoW64 = false);

		/**
		 * Creates a RegistryKey object to reference a key at a given path.
		 *
		 * @param path The path of the registry key to reference.
		 */
		RegistryKey(std::wstring path, bool WoW64 = false);

		/**
		 * \brief Construct a RegistryKey object reference to a key present under another RegistryKey object.
		 * 
		 * \param baseKey The base key.
		 * \param subkeyName The relative path to the base key.
		 * \param WoW64 Indicate whether this instance should refer to the WoW64 version of a key. For keys without 
		 *        WoW64 versions, this has no effect. If Wow6432node is part of the provided path, this value is ignored.
		 */
		RegistryKey(const RegistryKey& baseKey, const std::wstring& subkeyName, bool wow64 = false);

		/** Copy operator overload */
		RegistryKey& operator=(const RegistryKey& key) noexcept;

		/** Move operator overload */
		RegistryKey& operator=(RegistryKey&& key) noexcept;

	private:

		/**
		 * This class handles reference tracking for registry key handles
		 */
		class Tracker {
		private:

			/// A mapping of HKEYs to the number of references to that key
			std::unordered_map<HKEY, int> counts;

			/// A critical section guarding access to counts
			CriticalSection hGuard;

		public:

			explicit Tracker();

			/**
			 * Increments the number of references for hKey
			 *
			 * @param hKey The handle to increment references for
			 */
			void Increment(IN HKEY hKey);

			/**
			 * Decrements the number of references for hKey, closing the handle if it reaches zero
			 *
			 * @param hKey The handle to decrement references for
			 */
			void Decrement(IN HKEY hKey);

			/**
			 * Gets the number of references to a given HKEY
			 *
			 * @param hKey The HKEY to check the number of references for
			 *
			 * @return The number of references to hKey
			 */
			int Get(IN HKEY hKey);
		};

		static std::shared_ptr<RegistryKey::Tracker> __tracker;

		std::shared_ptr<Tracker> tracker;

		HKEY hkBackingKey;

		bool bKeyExists;
		bool bWow64;

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
		bool ValueExists(const std::wstring& wsValueName) const;

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
		 *	       an empty memory wrapper if the value is not present.
		 */
		AllocationWrapper GetRawValue(const std::wstring& wsValueName) const;

		/**
		 * Writes bytes to a given value under the key referenced by this object.
		 *
		 * @param name The name of the value to set
		 * @param bytes The bytes to write to the value
		 * @param type The datatype of the value
		 *
		 * @return True if the value was successfully set; false otherwise
		 */
		bool SetRawValue(const std::wstring& name, AllocationWrapper bytes, DWORD type = REG_BINARY) const;

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
		std::optional<T> GetValue(const std::wstring& wsValueName) const;

		/**
		 * Returns the type of a value under the currently referenced registry key.
		 * Currently, this only supports REG_SZ, REG_EXPAND_SZ, REG_DWORD, and REG_MULTI_SZ.
		 *
		 * @param wsValueName The name of the value to check
		 *
		 * @return An optional containing the registry type, or nullopt if the value does not exist or
		 *		   an error ocurred.
		 */
		std::optional<RegistryType> GetValueType(const std::wstring& wsValueName) const;

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
		bool SetValue(const std::wstring& name, T value, DWORD size = sizeof(T), DWORD type = REG_BINARY) const;

		template<>
		bool RegistryKey::SetValue(const std::wstring& name, std::vector<std::wstring> value, DWORD _size, DWORD type) const{
			SIZE_T size = 1;
			for(auto string : value){
				size += (string.length() + 1);
			}

			auto data = new WCHAR[size];
			auto allocation = AllocationWrapper{ data, static_cast<DWORD>(size * sizeof(WCHAR)), AllocationWrapper::CPP_ARRAY_ALLOC };
			unsigned ptr = 0;

			for(auto string : value){
				LPCWSTR lpRawString = string.c_str();
				for(unsigned i = 0; i < string.length() + 1; i++){
					if(ptr < size){
						data[ptr++] = lpRawString[i];
					}
				}
			}

			if(ptr < size){
				data[ptr] = { static_cast<WCHAR>(0) };
			}

			bool succeeded = SetRawValue(name, allocation, REG_MULTI_SZ);

			return succeeded;
		}

		/**
		 * Sets data for a specified value under the referenced key given a RegistryData object wrapping the underlying
		 * data
		 *
		 * @param name The name of the value to set.
		 * @param value The data to write to the value.
		 *
		 * @return True if the value was successfully set; false otherwise.
		 */
		bool SetDataValue(const std::wstring& name, RegistryData value) const;

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
		 * Returns a list of subkey names under the currently referenced registry key.
		 *
		 * @return a list of subkey names under the currently referenced registry key.
		 */
		std::vector<std::wstring> EnumerateSubkeyNames() const;

		/**
		 * Returns the full path of the referenced registry key witout the Hive.
		 *
		 * @return the full path of the referenced registry key without the Hive.
		 */
		std::wstring GetNameWithoutHive() const;

		/**
		 * Returns the full path of the referenced registry key.
		 *
		 * @return the full path of the referenced registry key.
		 */
		std::wstring GetName() const;

		/**
		 * Returns the full path of the referenced registry key.
		 *
		 * @return the full path of the referenced registry key.
		 */
		virtual std::wstring ToString() const;

		/**
		 * Override the < operator so registry keys can be used in sets, maps, and trees.
		 *
		 * @param key The key to compare
		 *
		 * @return true or false
		 */
		bool operator<(const RegistryKey& key) const;

		/**
		 * Override the == operator for comparisons.
		 *
		 * @param key The key to compare
		 *
		 * @return true or false
		 */
		bool operator==(const RegistryKey& key) const;

		/**
		 * Removes a value from the referenced registry key.
		 *
		 * @param wsValueName The name of the value to be removed
		 *
		 * @return a boolean indicating whether the value was successfully removed
		 */
		bool RemoveValue(const std::wstring& wsValueName) const;

		/**
		 * \brief Deletes the specified subkey under the referenced registry key, all its subkeys, and all its values
		 * 
		 * \param name The name of the subkey to delete.
		 * 
		 * \return True if the subkey no longer exists.
		 */
		bool DeleteSubkey(const std::wstring& subkey) const;

		operator HKEY() const;
	};
}

template<>
struct std::hash<Registry::RegistryKey> {
	size_t operator()(
		IN CONST Registry::RegistryKey& key
		) const;
};