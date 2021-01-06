#include "mitigation/policy/RegistryPolicy.h"

#include "util/StringUtils.h"

#include "mitigation/policy/SubkeyPolicy.h"
#include "mitigation/policy/ValuePolicy.h"
#include "user/bluespawn.h"
#include "util/StringUtils.h"

#include <assert.h>

RegistryPolicy::RegistryPolicy(const RegistryKey& key,
                               const std::wstring& name,
                               EnforcementLevel level,
                               const std::optional<std::wstring>& description,
                               const std::optional<Version>& min,
                               const std::optional<Version>& max) :
    MitigationPolicy(name, level, description, min, max),
    key{ key } {}

RegistryPolicy::ValuePolicy::ValuePolicy(const RegistryKey& key,
                                         const std::wstring& valueName,
                                         const RegistryData& data,
                                         ValuePolicyType policyType,
                                         const std::wstring& name,
                                         EnforcementLevel level,
                                         const std::optional<std::wstring>& description,
                                         const std::optional<RegistryData>& replacement,
                                         const std::optional<Version>& min,
                                         const std::optional<Version>& max) :
    RegistryPolicy(key, name, level, description, min, max),
    valueName{ valueName }, data{ data }, policyType{ policyType }, replacement{ replacement } {}

RegistryPolicy::ValuePolicy::ValuePolicy(json policy) : 
    RegistryPolicy(HKEY_LOCAL_MACHINE, L"", EnforcementLevel::None){
    assert(policy.find("name") != policy.end());
    assert(policy.find("enforcement-level") != policy.end());
    assert(policy.find("key-path") != policy.end());
    assert(policy.find("value-name") != policy.end());
    assert(policy.find("data-value") != policy.end());
    assert(policy.find("data-type") != policy.end());
    assert(policy.find("registry-value-policy-type") != policy.end());

    name = StringToWidestring(policy["name"].get<std::string>());
    description = policy.find("description") != policy.end() ? 
        std::optional<std::wstring>(StringToWidestring(policy["description"].get<std::string>())) : std::nullopt;

    auto levelString{ ToLowerCaseA(policy["enforcement-level"].get<std::string>()) };
    if(levelString == "low"){ level = EnforcementLevel::Low; }
    else if(levelString == "moderate"){ level = EnforcementLevel::Moderate; }
    else if(levelString == "high"){ level = EnforcementLevel::High; }
    else throw std::exception(("Unknown enforcement level: " + levelString).c_str());

    minVersion = policy.find("min-software-version") != policy.end() ?
        std::optional<Version>(StringToWidestring(policy["min-software-version"].get<std::string>())) : std::nullopt;
    maxVersion = policy.find("max-software-version") != policy.end() ?
        std::optional<Version>(StringToWidestring(policy["max-software-version"].get<std::string>())) : std::nullopt;

    key = RegistryKey(StringToWidestring(policy["key-path"].get<std::string>()));
    valueName = StringToWidestring(policy["value-name"].get<std::string>());

    auto typeString{ ToLowerCaseA(policy["registry-value-policy-type"].get<std::string>()) };
    if(typeString == "forbid-exact"){ policyType = ValuePolicyType::ForbidExact; }
    else if(typeString == "forbid-subset-of"){ policyType = ValuePolicyType::ForbidSubsetOf; }
    else if(typeString == "require-subset-of"){ policyType = ValuePolicyType::RequireSubsetOf; }
    else if(typeString == "require-exact"){ policyType = ValuePolicyType::RequireExact; }
    else if(typeString == "require-as-subset"){ policyType = ValuePolicyType::RequireAsSubset; }
    else throw std::exception(("Unknown registry policy type: " + typeString).c_str());

    auto datatypeString{ ToLowerCaseA(policy["data-type"].get<std::string>()) };
    if(datatypeString == "reg_dword"){ 
        assert(typeString == "forbid-exact" || typeString == "require-exact");
        data = policy["data-value"].get<DWORD>();
    } else if(datatypeString == "reg_sz"){
        assert(typeString == "forbid-exact" || typeString == "require-exact");
        data = StringToWidestring(policy["data-value"].get<std::string>());
    }
    else if(datatypeString == "reg_multi_sz"){ 
        std::vector<std::wstring> dataValue{};
        for(auto& entry : policy["data-value"]){
            dataValue.emplace_back(StringToWidestring(entry.get<std::string>()));
        }
        data = dataValue;
    }
    else if(datatypeString == "reg_binary"){
        assert(typeString == "forbid-exact" || typeString == "require-exact");
        auto stringRepresentation{ policy["data-value"].get<std::string>() };
        auto len{ stringRepresentation.size() };
        AllocationWrapper dataValue(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len), len, 
                                    AllocationWrapper::HEAP_ALLOC);
        CopyMemory(dataValue, stringRepresentation.data(), len);
        data = dataValue;
    }
    else throw std::exception(("Unknown registry data type: " + datatypeString).c_str());
}

std::vector<std::wstring>& ReadMultiValue(RegistryValue& value, const std::wstring& name) {
    if(value.GetType() != RegistryType::REG_MULTI_SZ_T) {
        Bluespawn::io.InformUser(L"Mitigation policy `" + name + L"` is treating " + value.ToString() +
                                 L" as a REG_MULTI_SZ. This may lead to undesired behavior.");
        std::wstring elem;
        if(value.GetType() == RegistryType::REG_SZ_T) {
            elem = std::get<std::wstring>(value.data);
        } else if(value.GetType() == RegistryType::REG_DWORD_T) {
            elem = std::to_wstring(std::get<DWORD>(value.data));
        } else {
            throw std::exception("Unable to convert registry binary value to REG_MULTI_SZ");
        }
        value.type = RegistryType::REG_MULTI_SZ_T;
        value.data = std::vector<std::wstring>{ elem };
    }

    return std::get<std::vector<std::wstring>>(value.data);
}

bool RegistryPolicy::ValuePolicy::Enforce() const {
    if(IsEnforced()) {
        if(!MatchesSystem()) {
            if(policyType == ValuePolicyType::RequireExact) {
                return key.SetValue(valueName, data);
            } else if(policyType == ValuePolicyType::ForbidExact) {
                if(replacement) {
                    return key.SetValue(valueName, *replacement);
                } else {
                    return key.RemoveValue(valueName);
                }
            } else if(policyType == ValuePolicyType::RequireAsSubset) {
                auto curVal{ RegistryValue::Create(key, valueName) };
                if(!curVal) {
                    return key.SetValue(valueName, data);
                }

                try {
                    auto& regData{ ReadMultiValue(*curVal, GetPolicyName()) };
                    auto& reqData{ std::get<std::vector<std::wstring>>(data) };
                    for(auto& elem : reqData) {
                        bool found = false;
                        for(auto& present : regData) {
                            if(elem == present) {
                                found = true;
                            }
                        }
                        if(!found) {
                            regData.emplace_back(elem);
                        }
                    }
                    return key.SetValue(valueName, regData);
                } catch(std::exception& e) { return key.SetValue(valueName, data); }
            } else if(policyType == ValuePolicyType::RequireSubsetOf) {
                auto curVal{ RegistryValue::Create(key, valueName) };
                std::vector<std::wstring> fixedData{};

                try {
                    auto& regData{ ReadMultiValue(*curVal, GetPolicyName()) };
                    auto& reqData{ std::get<std::vector<std::wstring>>(data) };
                    for(auto& elem : regData) {
                        bool found = false;
                        for(auto& present : reqData) {
                            if(elem == present) {
                                found = true;
                            }
                        }
                        if(found) {
                            fixedData.emplace_back(elem);
                        }
                    }
                } catch(std::exception& e) {}   // exception came from ReadMultiValue; discard it
                return key.SetValue(valueName, fixedData);
            } else {
                auto curVal{ RegistryValue::Create(key, valueName) };
                std::vector<std::wstring> fixedData{};

                try {
                    auto& regData{ ReadMultiValue(*curVal, GetPolicyName()) };
                    auto& reqData{ std::get<std::vector<std::wstring>>(data) };
                    for(auto& elem : regData) {
                        bool found = false;
                        for(auto& present : reqData) {
                            if(elem == present) {
                                found = true;
                            }
                        }
                        if(!found) {
                            fixedData.emplace_back(elem);
                        }
                    }
                } catch(std::exception& e) {}   // exception came from ReadMultiValue; discard it
                return key.SetValue(valueName, fixedData);
            }
        } else {
            return true;
        }
    } else {
        return MatchesSystem();
    }
}

bool RegistryPolicy::ValuePolicy::MatchesSystem() const {
    if(policyType == ValuePolicyType::RequireExact) {
        return key.ValueExists(valueName) && RegistryValue::Create(key, valueName)->data == data;
    } else if(policyType == ValuePolicyType::ForbidExact) {
        return !key.ValueExists(valueName) || RegistryValue::Create(key, valueName)->data != data;
    } else if(policyType == ValuePolicyType::RequireAsSubset) {
        auto curVal{ RegistryValue::Create(key, valueName) };
        if(!curVal) {
            return false;
        }

        try {
            auto& regData{ ReadMultiValue(*curVal, GetPolicyName()) };
            auto& reqData{ std::get<std::vector<std::wstring>>(data) };
            for(auto& elem : reqData) {
                bool found = false;
                for(auto& present : regData) {
                    if(elem == present) {
                        found = true;
                    }
                }
                if(!found) {
                    return false;
                }
            }
            return true;
        } catch(std::exception& e) {
            Bluespawn::io.InformUser(StringToWidestring(e.what()));
            return false;
        }
    } else if(policyType == ValuePolicyType::RequireSubsetOf) {
        auto curVal{ RegistryValue::Create(key, valueName) };
        if(!curVal) {
            return true;
        }

        try {
            auto& regData{ ReadMultiValue(*curVal, GetPolicyName()) };
            auto& reqData{ std::get<std::vector<std::wstring>>(data) };
            for(auto& elem : regData) {
                bool found = false;
                for(auto& present : reqData) {
                    if(elem == present) {
                        found = true;
                    }
                }
                if(!found) {
                    return false;
                }
            }
            return true;
        } catch(std::exception& e) {
            Bluespawn::io.InformUser(StringToWidestring(e.what()));
            return false;
        }
    } else {
        auto curVal{ RegistryValue::Create(key, valueName) };
        if(!curVal) {
            return true;
        }

        try {
            auto& regData{ ReadMultiValue(*curVal, GetPolicyName()) };
            auto& reqData{ std::get<std::vector<std::wstring>>(data) };
            for(auto& elem : regData) {
                bool found = false;
                for(auto& present : reqData) {
                    if(elem == present) {
                        found = true;
                    }
                }
                if(found) {
                    return false;
                }
            }
            return true;
        } catch(std::exception& e) {
            Bluespawn::io.InformUser(StringToWidestring(e.what()));
            return false;
        }
    }
}

RegistryPolicy::SubkeyPolicy::SubkeyPolicy(const RegistryKey& key,
                                           const std::vector<std::wstring>& subkeyNames,
                                           SubkeyPolicyType policyType,
                                           const std::wstring& name,
                                           EnforcementLevel level,
                                           const std::optional<std::wstring>& description,
                                           const std::optional<Version>& min,
                                           const std::optional<Version>& max) :
    RegistryPolicy(key, name, level, description, min, max),
    subkeyNames(subkeyNames.begin(), subkeyNames.end()), policyType{ policyType } {}

RegistryPolicy::SubkeyPolicy::SubkeyPolicy(json policy) :
    RegistryPolicy(HKEY_LOCAL_MACHINE, L"", EnforcementLevel::None){
    assert(policy.find("name") != policy.end());
    assert(policy.find("enforcement-level") != policy.end());
    assert(policy.find("key-path") != policy.end());
    assert(policy.find("subkey-names") != policy.end());
    assert(policy.find("subkey-policy-type") != policy.end());

    name = StringToWidestring(policy["name"].get<std::string>());
    description = policy.find("description") != policy.end() ?
        std::optional<std::wstring>(StringToWidestring(policy["description"].get<std::string>())) : std::nullopt;

    auto levelString{ ToLowerCaseA(policy["enforcement-level"].get<std::string>()) };
    if(levelString == "low"){ level = EnforcementLevel::Low; } 
    else if(levelString == "moderate"){ level = EnforcementLevel::Moderate; } 
    else if(levelString == "high"){ level = EnforcementLevel::High; } 
    else throw std::exception(("Unknown enforcement level: " + levelString).c_str());

    minVersion = policy.find("min-software-version") != policy.end() ?
        std::optional<Version>(StringToWidestring(policy["min-software-version"].get<std::string>())) : std::nullopt;
    maxVersion = policy.find("max-software-version") != policy.end() ?
        std::optional<Version>(StringToWidestring(policy["max-software-version"].get<std::string>())) : std::nullopt;

    key = RegistryKey(StringToWidestring(policy["key-path"].get<std::string>()));

    auto typeString{ ToLowerCaseA(policy["subkey-policy-type"].get<std::string>()) };
    if(typeString == "blacklist"){ policyType = SubkeyPolicyType::Blacklist; } 
    else if(typeString == "whitelist"){ policyType = SubkeyPolicyType::Whitelist; } 
    else throw std::exception(("Unknown registry policy type: " + typeString).c_str());

    for(auto& entry : policy["data-value"]){
        subkeyNames.emplace(StringToWidestring(entry.get<std::string>()));
    }
}

bool RegistryPolicy::SubkeyPolicy::Enforce() const {
    if(IsEnforced()) {
        if(!MatchesSystem()) {
            auto subkeys{ key.EnumerateSubkeyNames() };
            if(policyType == SubkeyPolicyType::Whitelist) {
                for(auto& subkey : subkeys) {
                    if(subkeyNames.find(subkey) == subkeyNames.end()) {
                        key.DeleteSubkey(subkey);
                    }
                }
            } else {
                for(auto& subkey : subkeys) {
                    if(subkeyNames.find(subkey) != subkeyNames.end()) {
                        key.DeleteSubkey(subkey);
                    }
                }
            }
        }
    } else {
        return MatchesSystem();
    }
}

bool RegistryPolicy::SubkeyPolicy::MatchesSystem() const {
    auto subkeys{ key.EnumerateSubkeyNames() };
    if(policyType == SubkeyPolicyType::Whitelist) {
        for(auto& subkey : subkeys) {
            if(subkeyNames.find(subkey) == subkeyNames.end()) {
                return false;
            }
        }
    } else {
        for(auto& subkey : subkeys) {
            if(subkeyNames.find(subkey) != subkeyNames.end()) {
                return false;
            }
        }
    }
}
