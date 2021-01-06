#include "mitigation/policy/RegistryPolicy.h"

#include "util/StringUtils.h"

#include "mitigation/policy/SubkeyPolicy.h"
#include "mitigation/policy/ValuePolicy.h"
#include "user/bluespawn.h"
#include "util/StringUtils.h"

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
    assert(policy.find("key-path") != policy.end());
    assert(policy.find("name") != policy.end());
    // assert(policy.find("description") != policy.end());
    assert(policy.find("enforcement-level") != policy.end());
    // assert(policy.find("min-software-version") != policy.end());
    // assert(policy.find("max-software-version") != policy.end());
    assert(policy.find("value-name") != policy.end());
    assert(policy.find("data-value") != policy.end());
    assert(policy.find("data-type") != policy.end());
    assert(policy.find("registry-value-policy-type") != policy.end());

    key = RegistryKey(StringToWidestring(policy["key-path"]));
    name = StringToWidestring(policy["name"]);
    description = policy.find("description") != policy.end() ? 
        std::optional<std::wstring>(StringToWidestring(policy["description"].get<std::string>())) : std::nullopt;

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
