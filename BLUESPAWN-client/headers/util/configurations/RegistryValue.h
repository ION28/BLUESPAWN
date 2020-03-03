#pragma once
#include "util/log/Loggable.h"

#include "common/wrappers.hpp"

#include <vector>
#include <unordered_set>
#include <functional>
#include <string>
#include <variant>

namespace Registry {

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
	};
}