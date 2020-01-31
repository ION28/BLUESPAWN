#include "hunt/RegistryHunt.h"
#include "hunt/reaction/Reaction.h"

#include "util/log/HuntLogMessage.h"
#include "util/log/Log.h"

#include <regex>
#include <unordered_set>

namespace Registry {
	REG_SZ_CHECK CheckSzEqual = [](std::wstring s1, std::wstring s2){ return s1 == s2; };
	REG_SZ_CHECK CheckSzNotEqual = [](std::wstring s1, std::wstring s2){ return s1 != s2; };
	REG_SZ_CHECK CheckSzEmpty = [](std::wstring s1, std::wstring s2){ return s1.length() == 0; };
	REG_SZ_CHECK CheckSzRegexMatch = [](std::wstring s1, std::wstring s2){ return std::regex_match(s1, std::wregex(s2)); };
	REG_SZ_CHECK CheckSzRegexNotMatch = [](std::wstring s1, std::wstring s2){ return !std::regex_match(s1, std::wregex(s2)); };

	REG_DWORD_CHECK CheckDwordEqual = [](DWORD d1, DWORD d2){ return d1 == d2; };
	REG_DWORD_CHECK CheckDwordNotEqual = [](DWORD d1, DWORD d2){ return d1 != d2; };

	REG_BINARY_CHECK CheckBinaryEqual = [](MemoryWrapper<> s1, MemoryWrapper<> s2){ 
		return s1.MemorySize == s2.MemorySize && !memcmp(s1.address, s2.address, s1.MemorySize);
	};
	REG_BINARY_CHECK CheckBinaryNotEqual = [](MemoryWrapper<> s1, MemoryWrapper<> s2){
		return s1.MemorySize != s2.MemorySize || memcmp(s1.address, s2.address, s1.MemorySize);
	};
	REG_BINARY_CHECK CheckBinaryNull = [](MemoryWrapper<> s1, MemoryWrapper<> s2){ return s1.address == nullptr; };

	REG_MULTI_SZ_CHECK CheckMultiSzSubset = [](std::vector<std::wstring> s1, std::vector<std::wstring> s2){
		std::unordered_set<std::wstring> vals = { s2.begin(), s2.end() };
		for(auto string : s1){
			if(vals.find(string) == vals.end()){
				return false;
			}
		}
		return true;
	};
	REG_MULTI_SZ_CHECK CheckMultiSzExclusion = [](std::vector<std::wstring> s1, std::vector<std::wstring> s2){
		std::unordered_set<std::wstring> vals = { s2.begin(), s2.end() };
		for(auto string : s1){
			if(vals.find(string) != vals.end()){
				return false;
			}
		}
		return true;
	};
	REG_MULTI_SZ_CHECK CheckMultiSzEmpty = [](std::vector<std::wstring> s1, std::vector<std::wstring> s2){
		return s1.size() == 0;
	};

	RegistryCheck::RegistryCheck(std::wstring wValueName, RegistryType type, std::wstring wData,
		bool MissingBad, REG_SZ_CHECK check) :
		value{ wValueName, type, wData },
		MissingBad{ MissingBad },
		wCheck{ check }{}

	RegistryCheck::RegistryCheck(std::wstring wValueName, RegistryType type, DWORD dwData,
		bool MissingBad, REG_DWORD_CHECK check) :
		value{ wValueName, type, dwData },
		MissingBad{ MissingBad },
		dwCheck{ check }{}

	RegistryCheck::RegistryCheck(std::wstring wValueName, RegistryType type, MemoryWrapper<> lpData,
		bool MissingBad, REG_BINARY_CHECK check) :
		value{ wValueName, type, lpData },
		MissingBad{ MissingBad },
		lpCheck{ check }{}

	RegistryCheck::RegistryCheck(std::wstring wValueName, RegistryType type, std::vector<std::wstring> vData,
		bool MissingBad, REG_MULTI_SZ_CHECK check) :
		value{ wValueName, type, vData },
		MissingBad{ MissingBad },
		vCheck{ check }{}

	RegistryCheck::RegistryCheck(const RegistryCheck& copy) :
		value{ copy.value },
		MissingBad{ copy.MissingBad }{
		if(copy.value.type == RegistryType::REG_BINARY_T){
			lpCheck = copy.lpCheck;
		} else if(copy.value.type == RegistryType::REG_SZ_T || copy.value.type == RegistryType::REG_EXPAND_SZ_T){
			wCheck = copy.wCheck;
		} else if(copy.value.type == RegistryType::REG_MULTI_SZ_T){
			vCheck = copy.vCheck;
		} else {
			dwCheck = copy.dwCheck;
		}
	}

	RegistryCheck RegistryCheck::operator=(const RegistryCheck& copy){
		value = copy.value;
		MissingBad = copy.MissingBad;
		if(copy.value.type == RegistryType::REG_BINARY_T){
			lpCheck = copy.lpCheck;
		} else if(copy.value.type == RegistryType::REG_SZ_T || copy.value.type == RegistryType::REG_EXPAND_SZ_T){
			wCheck = copy.wCheck;
		} else if(copy.value.type == RegistryType::REG_MULTI_SZ_T){
			vCheck = copy.vCheck;
		} else {
			dwCheck = copy.dwCheck;
		}
		return *this;
	}

	RegistryType RegistryCheck::GetType() const {
		return value.type;
	}

	std::vector<RegistryValue> CheckValues(const RegistryKey& key, const std::vector<RegistryCheck> checks){
		std::vector<RegistryValue> vIdentifiedValues = {};

		LOG_VERBOSE(1, "Checking values under " << key.ToString());

		for(const RegistryCheck& check : checks){
			if(check.GetType() == RegistryType::REG_SZ_T || check.GetType() == RegistryType::REG_EXPAND_SZ_T){
				auto data = key.GetValue<std::wstring>(check.value.wValueName);
				if(!data.has_value()){
					if(check.MissingBad){
						LOG_INFO("Under key " << key << ", desired value " << check.value.wValueName << " was missing.");
						vIdentifiedValues.emplace_back(RegistryValue{ check.value.wValueName, check.GetType(), std::vector<std::wstring>{} });
					}
				} else if(!check.wCheck(*data, check.value.wData)){
					auto value = RegistryValue{ check.value.wValueName, check.GetType(), *data };
					LOG_INFO("Under key " << key << ", value " << check.value.wValueName << " had potentially malicious data " << value);
					vIdentifiedValues.emplace_back(value);
				}
			} else if(check.GetType() == RegistryType::REG_MULTI_SZ_T){
				auto data = key.GetValue<std::vector<std::wstring>>(check.value.wValueName);
				if(!data.has_value()){
					if(check.MissingBad){
						LOG_INFO("Under key " << key << ", desired value " << check.value.wValueName << " was missing.");
						vIdentifiedValues.emplace_back(RegistryValue{ check.value.wValueName, check.GetType(), std::wstring{} });
					}
				} else if(!check.vCheck(*data, check.value.vData)){
					auto value = RegistryValue{ check.value.wValueName, check.GetType(), *data };
					LOG_INFO("Under key " << key << ", value " << check.value.wValueName << " had potentially malicious data " << value);
					vIdentifiedValues.emplace_back(value);
				}
			} else if(check.GetType() == RegistryType::REG_DWORD_T){
				auto data = key.GetValue<DWORD>(check.value.wValueName);
				if(!data.has_value()){
					if(check.MissingBad){
						LOG_INFO("Under key " << key << ", desired value " << check.value.wValueName << " was missing.");
						vIdentifiedValues.emplace_back(RegistryValue{ check.value.wValueName, check.GetType(), 0 });
					}
				} else if(!check.dwCheck(*data, check.value.dwData)){
					auto value = RegistryValue{ check.value.wValueName, check.GetType(), *data };
					LOG_INFO("Under key " << key << ", value " << check.value.wValueName << " had potentially malicious data " << value);
					vIdentifiedValues.emplace_back(value);
				}
			} else if(check.GetType() == RegistryType::REG_BINARY_T){
				auto data = key.GetRawValue(check.value.wValueName);
				if(data.address == nullptr){
					if(check.MissingBad){
						LOG_INFO("Under key " << key << ", desired value " << check.value.wValueName << " was missing.");
						vIdentifiedValues.emplace_back(RegistryValue{ check.value.wValueName, check.GetType(), MemoryWrapper<>{ nullptr, 0 }});
					}
				} else if(!check.lpCheck(data, check.value.lpData)){
					auto value = RegistryValue{ check.value.wValueName, check.GetType(), *data };
					LOG_INFO("Under key " << key << ", value " << check.value.wValueName << " had potentially malicious data " << value);
					vIdentifiedValues.emplace_back(value);
				}
			}
		}
		return vIdentifiedValues;
	}

	RegistryCheck::~RegistryCheck(){
		switch(value.type){
		case RegistryType::REG_SZ_T:
		case RegistryType::REG_EXPAND_SZ_T:
			wCheck.~function();
			break;
		case RegistryType::REG_BINARY_T:
			lpCheck.~function();
			break;
		case RegistryType::REG_DWORD_T:
			dwCheck.~function();
			break;
		case RegistryType::REG_MULTI_SZ_T:
			vCheck.~function();
			break;
		}
		value.~RegistryValue();
	}

	std::vector<RegistryValue> CheckKeyValues(const RegistryKey& key){
		auto values = key.EnumerateValues();
		std::vector<RegistryValue> vRegValues = {};

		for(const auto& value : values){
			auto type = key.GetValueType(value);
			if(type == RegistryType::REG_SZ_T || type == RegistryType::REG_EXPAND_SZ_T){
				auto data = key.GetValue<std::wstring>(value);
				auto regValue = RegistryValue{ value, *type, (!data ? L"" : *data) };

				LOG_INFO("Under key " << key << ", value " << value << " was present with data " << regValue);

				vRegValues.emplace_back(regValue);
			} else if(type == RegistryType::REG_MULTI_SZ_T){
				auto data = key.GetValue<std::vector<std::wstring>>(value);
				auto regValue = RegistryValue{ value, *type, (!data ? std::vector<std::wstring>{} : *data) };

				LOG_INFO("Under key " << key << ", value " << value << " was present with data " << regValue);

				vRegValues.emplace_back(regValue);
			} else if(type == RegistryType::REG_DWORD_T){
				auto data = key.GetValue<DWORD>(value);
				auto regValue = RegistryValue{ value, *type, (!data ? 0 : *data) };

				LOG_INFO("Under key " << key << ", value " << value << " was present with data " << regValue);

				vRegValues.emplace_back(regValue);
			} else {
				auto data = key.GetRawValue(value);
				auto regValue = RegistryValue{ value, *type, data };

				LOG_INFO("Under key " << key << ", value " << value << " was present with data " << regValue);

				vRegValues.emplace_back(regValue);
			}
		}

		return vRegValues;
	}

	std::vector<RegistryKey> CheckSubkeys(const RegistryKey& key){
		return key.EnumerateSubkeys();
	}
}