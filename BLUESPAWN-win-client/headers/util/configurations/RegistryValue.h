#pragma once
#include "Registry.h"
#include "util/log/Loggable.h"

#include "util/wrappers.hpp"

#include <vector>
#include <unordered_set>
#include <functional>
#include <string>
#include <variant>

namespace Registry {

	/**
	 * A container class for registry values and associated data.
	 */
	struct RegistryValue : public Loggable {
		RegistryKey key;
		std::wstring wValueName;
		RegistryType type;

		RegistryData data{};

		RegistryValue(const RegistryKey& key, const std::wstring& wValueName, std::wstring&& wData);
		RegistryValue(const RegistryKey& key, const std::wstring& wValueName, DWORD&& dwData);
		RegistryValue(const RegistryKey& key, const std::wstring& wValueName, AllocationWrapper&& lpData);
		RegistryValue(const RegistryKey& key, const std::wstring& wValueName, std::vector<std::wstring>&& wData);

		/**
		 * Attempts to create a RegistryValue object from a value name and the key under which the value can be found
		 *
		 * @param key The key under which the value can be found
		 * @param name The name of the value
		 *
		 * @return An optional containing the RegistryValue object if the value was found, and nullopt otherwise
		 */
		static std::optional<RegistryValue> Create(
			IN CONST RegistryKey& key,
			IN CONST std::wstring& name
		);

		RegistryType GetType() const;

		std::wstring GetPrintableName() const;

		virtual std::wstring ToString() const;

		bool operator==(const RegistryValue& value) const;
		bool operator<(const RegistryValue& value) const;
	};
}