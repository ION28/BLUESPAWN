#pragma once
#include "util/log/Loggable.h"

#include "common/wrappers.hpp"

#include <vector>
#include <unordered_set>
#include <functional>
#include <string>

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

	/**
	 * A container class for registry values and associated data.
	 */
	struct RegistryValue : public Loggable {
		std::wstring wValueName;
		RegistryType type;

		// Only one of these will be valid data; which one will be indicated by `type`
		std::wstring wData = {};
		DWORD dwData = {};
		AllocationWrapper lpData = { nullptr, 0 };
		std::vector<std::wstring> vData = {};

		RegistryValue(std::wstring wValueName, RegistryType type, std::wstring wData);
		RegistryValue(std::wstring wValueName, RegistryType type, DWORD dwData);
		RegistryValue(std::wstring wValueName, RegistryType type, AllocationWrapper lpData);
		RegistryValue(std::wstring wValueName, RegistryType type, std::vector<std::wstring> wData);

		RegistryType GetType() const;

		virtual std::wstring ToString() const;
	};
}