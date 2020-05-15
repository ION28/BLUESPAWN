#pragma once
#include "Registry.h"
#include "util/log/Loggable.h"

#include "common/wrappers.hpp"

#include <vector>
#include <unordered_set>
#include <functional>
#include <string>
#include <variant>

namespace Registry {

	typedef std::variant<std::wstring, DWORD, AllocationWrapper, std::vector<std::wstring>> RegistryData;

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

		RegistryType GetType() const;

		virtual std::wstring ToString() const;

		bool operator==(const RegistryValue& value) const;
	};
}