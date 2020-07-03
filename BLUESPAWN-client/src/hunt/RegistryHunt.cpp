#include "hunt/RegistryHunt.h"
#include "util/log/Log.h"

#include <regex>
#include <set>

namespace Registry {
	REG_SZ_CHECK CheckSzEqual = [](const std::wstring& s1, const std::wstring& s2){ return s1 == s2; };
	REG_SZ_CHECK CheckSzNotEqual = [](const std::wstring& s1, const std::wstring& s2){ return s1 != s2; };
	REG_SZ_CHECK CheckSzEmpty = [](const std::wstring& s1, const std::wstring& s2){ return s1.length() == 0; };
	REG_SZ_CHECK CheckSzRegexMatch = [](const std::wstring& s1, const std::wstring& s2){ return std::regex_match(s1, std::wregex(s2)); };
	REG_SZ_CHECK CheckSzRegexNotMatch = [](const std::wstring& s1, const std::wstring& s2){ return !std::regex_match(s1, std::wregex(s2)); };

	REG_DWORD_CHECK CheckDwordEqual = [](DWORD d1, DWORD d2){ return d1 == d2; };
	REG_DWORD_CHECK CheckDwordNotEqual = [](DWORD d1, DWORD d2){ return d1 != d2; };

	REG_BINARY_CHECK CheckBinaryEqual = [](const AllocationWrapper& s1, const AllocationWrapper& s2){
		return s1.CompareMemory(s2);
	};
	REG_BINARY_CHECK CheckBinaryNotEqual = [](const AllocationWrapper& s1, const AllocationWrapper& s2){
		return !s1.CompareMemory(s2);
	};
	REG_BINARY_CHECK CheckBinaryNull = [](const AllocationWrapper& s1, const AllocationWrapper& s2){ return !s1; };

	REG_MULTI_SZ_CHECK CheckMultiSzSubset = [](const std::vector<std::wstring>& s1, const std::vector<std::wstring>& s2){
		std::unordered_set<std::wstring> vals = { s2.begin(), s2.end() };
		for(auto string : s1){
			if(vals.find(string) == vals.end()){
				return false;
			}
		}
		return true;
	};
	REG_MULTI_SZ_CHECK CheckMultiSzExclusion = [](const std::vector<std::wstring>& s1, const std::vector<std::wstring>& s2){
		std::unordered_set<std::wstring> vals = { s2.begin(), s2.end() };
		for(auto string : s1){
			if(vals.find(string) != vals.end()){
				return false;
			}
		}
		return true;
	};
	REG_MULTI_SZ_CHECK CheckMultiSzEmpty = [](const std::vector<std::wstring>& s1, const std::vector<std::wstring>& s2){
		return s1.size() == 0;
	};

	RegistryCheck::RegistryCheck(std::wstring&& wValueName, std::wstring&& wData, bool MissingBad, const REG_SZ_CHECK& check) :
		name{ std::forward<std::wstring>(wValueName) },
		value{ std::forward<std::wstring>(wData) },
		type{ RegistryType::REG_SZ_T },
		MissingBad{ MissingBad },
		check{ check }{}

	RegistryCheck::RegistryCheck(std::wstring&& wValueName, DWORD&& dwData, bool MissingBad, const REG_DWORD_CHECK& check) :
		name{ std::forward<std::wstring>(wValueName) },
		value{ std::forward<DWORD>(dwData) },
		type{ RegistryType::REG_DWORD_T },
		MissingBad{ MissingBad },
		check{ check }{}

	RegistryCheck::RegistryCheck(std::wstring&& wValueName, AllocationWrapper&& lpData, bool MissingBad, const REG_BINARY_CHECK& check) :
		name{ std::forward<AllocationWrapper>(lpData) },
		value{ std::forward<std::wstring>(wValueName) },
		type{ RegistryType::REG_BINARY_T },
		MissingBad{ MissingBad },
		check{ check }{}

	RegistryCheck::RegistryCheck(std::wstring&& wValueName, std::vector<std::wstring>&& vData, bool MissingBad, const REG_MULTI_SZ_CHECK& check) :
		name{ std::forward<std::wstring>(wValueName) },
		value{ std::forward<std::vector<std::wstring>>(vData) },
		type{ RegistryType::REG_MULTI_SZ_T },
		MissingBad{ MissingBad },
		check{ check }{}

	RegistryType RegistryCheck::GetType() const {
		return type;
	}

	bool RegistryCheck::operator()(const RegistryData& data) const {
		if(type == RegistryType::REG_DWORD_T){
			return (std::get<REG_DWORD_CHECK>(check))(std::get<DWORD>(data), std::get<DWORD>(value));
		} else if(type == RegistryType::REG_SZ_T){
			return (std::get<REG_SZ_CHECK>(check))(std::get<std::wstring>(data), std::get<std::wstring>(value));
		} else if(type == RegistryType::REG_MULTI_SZ_T){
			return (std::get<REG_MULTI_SZ_CHECK>(check))(std::get<std::vector<std::wstring>>(data), std::get<std::vector<std::wstring>>(value));
		} else {
			return (std::get<REG_BINARY_CHECK>(check))(std::get<AllocationWrapper>(data), std::get<AllocationWrapper>(value));
		}
	}

	std::vector<RegistryValue> CheckValues(const HKEY& hkHive, const std::wstring& path, const std::vector<RegistryCheck>& checks, bool CheckWow64, bool CheckUsers){
		std::vector<RegistryValue> vIdentifiedValues{};
		std::vector<RegistryKey> vKeys{ RegistryKey{hkHive, path} };
		if(CheckWow64){
			RegistryKey Wow64Key{ hkHive, path, true };
			if(Wow64Key.Exists() && std::count(vKeys.begin(), vKeys.end(), Wow64Key) == 0){
				vKeys.emplace_back(Wow64Key);
			}
		}
		if(CheckUsers){
			std::vector<RegistryKey> hkUserHives{ RegistryKey{HKEY_USERS}.EnumerateSubkeys() };
			for(auto& hive : hkUserHives){
				RegistryKey key{ HKEY(hive), path, false };
				if(key.Exists() && std::count(vKeys.begin(), vKeys.end(), key) == 0){
					vKeys.emplace_back(key);
				}
				if(CheckWow64){
					RegistryKey Wow64Key{ HKEY(hive), path, true };
					if(Wow64Key.Exists() && std::count(vKeys.begin(), vKeys.end(), Wow64Key) == 0){
						vKeys.emplace_back(Wow64Key);
					}
				}
			}
		}

		for(auto& key : vKeys){
			LOG_VERBOSE(1, "Checking values under " << key.ToString());

			for(const RegistryCheck& check : checks){
				if(check.GetType() == RegistryType::REG_SZ_T || check.GetType() == RegistryType::REG_EXPAND_SZ_T){
					auto data = key.GetValue<std::wstring>(check.name);
					if(!data.has_value()){
						if(check.MissingBad){
							LOG_INFO(3, "Under key " << key << ", desired value " << check.name << " was missing.");
							vIdentifiedValues.emplace_back(RegistryValue{ key, check.name, std::move(std::wstring{}) });
						}
					} else if(!check(*data)){
						auto value = RegistryValue{ key, check.name, std::move(*data) };
						LOG_INFO(2, "Under key " << key << ", value " << value.GetPrintableName() << " had potentially malicious data " << value);
						vIdentifiedValues.emplace_back(value);
					}
				} else if(check.GetType() == RegistryType::REG_MULTI_SZ_T){
					auto data = key.GetValue<std::vector<std::wstring>>(check.name);
					if(!data.has_value()){
						if(check.MissingBad){
							LOG_INFO(3, "Under key " << key << ", desired value " << check.name << " was missing.");
							vIdentifiedValues.emplace_back(RegistryValue{ key, check.name, std::move(std::vector<std::wstring>{}) });
						}
					} else if(!check(*data)){
						auto value = RegistryValue{ key, check.name, std::move(*data) };
						LOG_INFO(2, "Under key " << key << ", value " << value.GetPrintableName() << " had potentially malicious data " << value);
						vIdentifiedValues.emplace_back(value);
					}
				} else if(check.GetType() == RegistryType::REG_DWORD_T){
					auto data = key.GetValue<DWORD>(check.name);
					if(!data.has_value()){
						if(check.MissingBad){
							LOG_INFO(3, "Under key " << key << ", desired value " << check.name << " was missing.");
							vIdentifiedValues.emplace_back(RegistryValue{ key, check.name, std::move(0) });
						}
					} else if(!check(*data)){
						auto value = RegistryValue{ key, check.name, std::move(*data) };
						LOG_INFO(2, "Under key " << key << ", value " << value.GetPrintableName() << " had potentially malicious data " << value);
						vIdentifiedValues.emplace_back(value);
					}
				} else if(check.GetType() == RegistryType::REG_BINARY_T){
					auto data = key.GetRawValue(check.name);
					if(!data){
						if(check.MissingBad){
							LOG_INFO(3, "Under key " << key << ", desired value " << check.name << " was missing.");
							vIdentifiedValues.emplace_back(RegistryValue{ key, check.name, std::move(AllocationWrapper{ nullptr, 0 }) });
						}
					} else if(!check(data)){
						auto value = RegistryValue{ key, check.name, std::move(data) };
						LOG_INFO(2, "Under key " << key << ", value " << value.GetPrintableName() << " had potentially malicious data " << value);
						vIdentifiedValues.emplace_back(value);
					}
				}
			}
		}
		return vIdentifiedValues;
	}

	std::vector<RegistryValue> CheckKeyValues(const HKEY& hkHive, const std::wstring& path, bool CheckWow64, bool CheckUsers){
		std::vector<RegistryValue> vIdentifiedValues{};
		std::vector<RegistryKey> vKeys{ RegistryKey{hkHive, path} };
		if(CheckWow64){
			RegistryKey Wow64Key{ hkHive, path, true };
			if(Wow64Key.Exists() && std::count(vKeys.begin(), vKeys.end(), Wow64Key) == 0){
				vKeys.emplace_back(Wow64Key);
			}
		}
		if(CheckUsers){
			std::vector<RegistryKey> hkUserHives{ RegistryKey{HKEY_USERS}.EnumerateSubkeys() };
			for(auto& hive : hkUserHives){
				RegistryKey key{ HKEY(hive), path, false };
				if(key.Exists() && std::count(vKeys.begin(), vKeys.end(), key) == 0){
					vKeys.emplace_back(key);
				}
				if(CheckWow64){
					RegistryKey Wow64Key{ HKEY(hive), path, true };
					if(Wow64Key.Exists() && std::count(vKeys.begin(), vKeys.end(), Wow64Key) == 0){
						vKeys.emplace_back(Wow64Key);
					}
				}
			}
		}

		std::vector<RegistryValue> vRegValues = {};
		for(auto& key : vKeys){
			auto values = key.EnumerateValues();

			for(const auto& value : values){
				auto type = key.GetValueType(value);
				if(type == RegistryType::REG_SZ_T || type == RegistryType::REG_EXPAND_SZ_T){
					auto data = key.GetValue<std::wstring>(value);
					auto regValue = RegistryValue{ key, value, std::move(!data ? L"" : *data) };

					LOG_INFO(2, "Under key " << key << ", value " << regValue.GetPrintableName() << " was present with data " << regValue);

					vRegValues.emplace_back(regValue);
				} else if(type == RegistryType::REG_MULTI_SZ_T){
					auto data = key.GetValue<std::vector<std::wstring>>(value);
					auto regValue = RegistryValue{ key, value, std::move(!data ? std::vector<std::wstring>{} : *data) };

					LOG_INFO(2, "Under key " << key << ", value " << regValue.GetPrintableName() << " was present with data " << regValue);

					vRegValues.emplace_back(regValue);
				} else if(type == RegistryType::REG_DWORD_T){
					auto data = key.GetValue<DWORD>(value);
					auto regValue = RegistryValue{ key, value, std::move(!data ? 0 : *data) };

					LOG_INFO(2, "Under key " << key << ", value " << regValue.GetPrintableName() << " was present with data " << regValue);

					vRegValues.emplace_back(regValue);
				} else {
					auto data = key.GetRawValue(value);
					auto regValue = RegistryValue{ key, value, std::move(data) };

					LOG_INFO(2, "Under key " << key << ", value " << regValue.GetPrintableName() << " was present with data " << regValue);

					vRegValues.emplace_back(regValue);
				}
			}
		}

		return vRegValues;
	}

	std::vector<RegistryKey> CheckSubkeys(const HKEY& hkHive, const std::wstring& path, bool CheckWow64, bool CheckUsers){
		std::vector<RegistryValue> vIdentifiedValues{};
		std::vector<RegistryKey> vKeys{ RegistryKey{hkHive, path} };
		if(CheckWow64){
			RegistryKey Wow64Key{ hkHive, path, true };
			if(Wow64Key.Exists() && std::count(vKeys.begin(), vKeys.end(), Wow64Key) == 0){
				vKeys.emplace_back(Wow64Key);
			}
		}
		if(CheckUsers){
			std::vector<RegistryKey> hkUserHives{ RegistryKey{HKEY_USERS}.EnumerateSubkeys() };
			for(auto& hive : hkUserHives){
				RegistryKey key{ HKEY(hive), path, false };
				if(key.Exists() && std::count(vKeys.begin(), vKeys.end(), key) == 0){
					vKeys.emplace_back(key);
				}
				if(CheckWow64){
					RegistryKey Wow64Key{ HKEY(hive), path, true };
					if(Wow64Key.Exists() && std::count(vKeys.begin(), vKeys.end(), Wow64Key) == 0){
						vKeys.emplace_back(Wow64Key);
					}
				}
			}
		}

		std::vector<RegistryKey> subkeys{};
		for(auto& key : vKeys){
			auto& subs = key.EnumerateSubkeys();
			for(auto& sub : subs){
				subkeys.emplace_back(sub);
			}
		}
		return subkeys;
	}
}
