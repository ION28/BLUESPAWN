#include "mitigation/policy/RegistryPolicy.h"

#include <assert.h>

#include <regex>

#include "util/StringUtils.h"

#include "mitigation/policy/SubkeyPolicy.h"
#include "mitigation/policy/ValuePolicy.h"
#include "user/bluespawn.h"

RegistryPolicy::RegistryPolicy(const RegistryKey& key,
                               const std::wstring& name,
                               EnforcementLevel level,
                               const std::optional<std::wstring>& description,
                               const std::optional<Version>& min,
                               const std::optional<Version>& max) :
    MitigationPolicy(name, level, description, min, max),
    keys{ key } {}

bool NameIsMatch(const std::wstring& subkeyName, std::wstring request) {
    for(auto find{ request.find(L"*") }; find != std::string::npos; find = request.find(L"*", find + 2)) {
        request.replace(request.begin() + find, request.begin() + find + 1, L".*");
    }
    return std::regex_match(ToLowerCaseW(subkeyName), std::wregex{ ToLowerCaseW(request) });
}

RegistryPolicy::RegistryPolicy(json policy) : MitigationPolicy(policy) {
    assert(policy.find("key-path") != policy.end());
    auto keyPath(StringToWidestring(policy["key-path"].get<std::string>()));
    auto keyPathParts{ SplitStringW(keyPath, L"\\") };
    bool care{ !wcscmp(keyPath.c_str(), L"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer") };
    std::vector<RegistryKey> keys{ RegistryKey(keyPathParts[0]) };
    for(auto idx = 1; idx < keyPathParts.size(); idx++) {
        std::vector<RegistryKey> children{};
        for(auto& key : keys) {
            if(keyPathParts[idx].find(L'*') != std::wstring::npos){
                for(auto& subkeyName : key.EnumerateSubkeyNames()){
                    if(NameIsMatch(subkeyName, keyPathParts[idx])){
                        children.emplace_back(RegistryKey{ key, subkeyName });
                    }
                }
            } else{
                children.emplace_back(RegistryKey{ key, keyPathParts[idx] });
            }
        }
        keys = children;
    }
    this->keys = keys;
}

ValuePolicy::ValuePolicy(const RegistryKey& key,
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

ValuePolicy::ValuePolicy(json policy) : RegistryPolicy(policy) {
    assert(policy.find("value-name") != policy.end());
    assert(policy.find("registry-value-policy-type") != policy.end());
    valueName = StringToWidestring(policy["value-name"].get<std::string>());

    auto typeString{ ToLowerCaseA(policy["registry-value-policy-type"].get<std::string>()) };
    if(typeString == "forbid-exact") {
        policyType = ValuePolicyType::ForbidExact;
    } else if(typeString == "forbid-subset-of") {
        policyType = ValuePolicyType::ForbidSubsetOf;
    } else if(typeString == "require-subset-of") {
        policyType = ValuePolicyType::RequireSubsetOf;
    } else if(typeString == "require-exact") {
        policyType = ValuePolicyType::RequireExact;
    } else if(typeString == "require-as-subset") {
        policyType = ValuePolicyType::RequireAsSubset;
    } else if(typeString == "forbid-value") {
        policyType = ValuePolicyType::ForbidValue;
    } else
        throw std::exception(("Unknown registry policy type: " + typeString).c_str());

    if(policyType != ValuePolicyType::ForbidValue) {
        assert(policy.find("data-value") != policy.end());
        assert(policy.find("data-type") != policy.end());

        auto datatypeString{ ToLowerCaseA(policy["data-type"].get<std::string>()) };
        if(datatypeString == "reg_dword") {
            assert(typeString == "forbid-exact" || typeString == "require-exact");
            data = policy["data-value"].get<DWORD>();
        } else if(datatypeString == "reg_sz") {
            assert(typeString == "forbid-exact" || typeString == "require-exact");
            data = StringToWidestring(policy["data-value"].get<std::string>());
        } else if(datatypeString == "reg_multi_sz") {
            std::vector<std::wstring> dataValue{};
            for(auto& entry : policy["data-value"]) {
                dataValue.emplace_back(StringToWidestring(entry.get<std::string>()));
            }
            data = dataValue;
        } else if(datatypeString == "reg_binary") {
            assert(typeString == "forbid-exact" || typeString == "require-exact");
            auto stringRepresentation{ policy["data-value"].get<std::string>() };
            auto len{ stringRepresentation.size() };
            AllocationWrapper dataValue(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len), len,
                                        AllocationWrapper::HEAP_ALLOC);
            CopyMemory(dataValue, stringRepresentation.data(), len);
            data = dataValue;
        } else
            throw std::exception(("Unknown registry data type: " + datatypeString).c_str());
    }
    if(policyType == ValuePolicyType::ForbidExact && policy.count("replacement-data-type") && 
       policy.count("replacement-data-value")){
        auto datatypeString{ ToLowerCaseA(policy["replacement-data-type"].get<std::string>()) };
        if(datatypeString == "reg_dword"){
            replacement = policy["replacement-data-value"].get<DWORD>();
        } else if(datatypeString == "reg_sz"){
            replacement = StringToWidestring(policy["replacement-data-value"].get<std::string>());
        } else if(datatypeString == "reg_multi_sz"){
            std::vector<std::wstring> dataValue{};
            for(auto& entry : policy["replacement-data-value"]){
                dataValue.emplace_back(StringToWidestring(entry.get<std::string>()));
            }
            replacement = dataValue;
        } else if(datatypeString == "reg_binary"){
            auto stringRepresentation{ policy["replacement-data-value"].get<std::string>() };
            auto len{ stringRepresentation.size() };
            AllocationWrapper dataValue(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len), len,
                                        AllocationWrapper::HEAP_ALLOC);
            CopyMemory(dataValue, stringRepresentation.data(), len);
            replacement = dataValue;
        } else
            throw std::exception(("Unknown registry data type: " + datatypeString).c_str());
    }
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

bool ValuePolicy::Enforce() {
    if(IsEnforced()) {
        if(policyType == ValuePolicyType::ForbidValue){
            for(auto& key : keys){
                if(key.ValueExists(valueName) && !key.RemoveValue(valueName)){
                    return false;
                }
            }
            return true;
        } else if(policyType == ValuePolicyType::RequireExact){
            for(auto& key : keys){
                if(!key.Exists()){
                    key.Create();
                }
                if(!key.ValueExists(valueName) || !(RegistryValue::Create(key, valueName)->data == data)){
                    if(!key.SetDataValue(valueName, data)){
                        return false;
                    }
                }
            }
            return true;
        } else if(policyType == ValuePolicyType::ForbidExact){
            for(auto& key : keys){
                if(key.ValueExists(valueName) && (RegistryValue::Create(key, valueName)->data == data)){
                    if(replacement){
                        if(!key.SetDataValue(valueName, *replacement)){
                            return false;
                        }
                    } else{
                        if(!key.RemoveValue(valueName)){
                            return false;
                        }
                    }
                }
            }
            return true;
        } else if(policyType == ValuePolicyType::RequireAsSubset){
            for(auto& key : keys){
                if(!key.Exists()){
                    key.Create();
                }
                auto curVal{ RegistryValue::Create(key, valueName) };
                if(!curVal){
                    if(!key.SetDataValue(valueName, data)){
                        return false;
                    }
                }

                try{
                    auto& regData{ ReadMultiValue(*curVal, GetPolicyName()) };
                    auto& reqData{ std::get<std::vector<std::wstring>>(data) };
                    for(auto& elem : reqData){
                        bool found = false;
                        for(auto& present : regData){
                            if(elem == present){
                                found = true;
                            }
                        }
                        if(!found){
                            regData.emplace_back(elem);
                        }
                    }
                    if(!key.SetValue(valueName, regData)){
                        return false;
                    }
                } catch(std::exception& e){
                    if(!key.SetDataValue(valueName, data)){
                        return false;
                    }
                }
            }
            return true;
        } else if(policyType == ValuePolicyType::RequireSubsetOf){
            for(auto& key : keys){
                auto curVal{ RegistryValue::Create(key, valueName) };
                std::vector<std::wstring> fixedData{};

                try{
                    auto& regData{ ReadMultiValue(*curVal, GetPolicyName()) };
                    auto& reqData{ std::get<std::vector<std::wstring>>(data) };
                    for(auto& elem : regData){
                        bool found = false;
                        for(auto& present : reqData){
                            if(elem == present){
                                found = true;
                            }
                        }
                        if(found){
                            fixedData.emplace_back(elem);
                        }
                    }
                } catch(std::exception& e){}   // exception came from ReadMultiValue; discard it
                if(!key.SetValue(valueName, fixedData)){
                    return false;
                }
            }
            return true;
        } else{
            for(auto& key : keys){
                auto curVal{ RegistryValue::Create(key, valueName) };
                std::vector<std::wstring> fixedData{};

                try{
                    auto& regData{ ReadMultiValue(*curVal, GetPolicyName()) };
                    auto& reqData{ std::get<std::vector<std::wstring>>(data) };
                    for(auto& elem : regData){
                        bool found = false;
                        for(auto& present : reqData){
                            if(elem == present){
                                found = true;
                            }
                        }
                        if(!found){
                            fixedData.emplace_back(elem);
                        }
                    }
                } catch(std::exception& e){}   // exception came from ReadMultiValue; discard it
                if(!key.SetValue(valueName, fixedData)){
                    return false;
                }
            }
            return true;
        }
    } else{
         return MatchesSystem();
    }
}

bool ValuePolicy::MatchesSystem() const {
    if(policyType == ValuePolicyType::ForbidValue) {
        for(auto& key : keys) {
            if(key.ValueExists(valueName)) {
                return false;
            }
        }
        return true;
    } else if(policyType == ValuePolicyType::RequireExact) {
        for(auto& key : keys){
            if(!key.ValueExists(valueName) || RegistryValue::Create(key, valueName)->data != data){
                return false;
            }
        }
        return true;
    } else if(policyType == ValuePolicyType::ForbidExact) {
        for(auto& key : keys){
            if(key.ValueExists(valueName) && RegistryValue::Create(key, valueName)->data == data){
                return false;
            }
        }
        return true;
    } else if(policyType == ValuePolicyType::RequireAsSubset) {
        for(auto& key : keys){
            auto curVal{ RegistryValue::Create(key, valueName) };
            if(!curVal){
                return false;
            }

            try{
                auto& regData{ ReadMultiValue(*curVal, GetPolicyName()) };
                auto& reqData{ std::get<std::vector<std::wstring>>(data) };
                for(auto& elem : reqData){
                    bool found = false;
                    for(auto& present : regData){
                        if(elem == present){
                            found = true;
                        }
                    }
                    if(!found){
                        return false;
                    }
                }
            } catch(std::exception& e){
                Bluespawn::io.InformUser(StringToWidestring(e.what()));
                return false;
            }
        }
        return true;
    } else if(policyType == ValuePolicyType::RequireSubsetOf) {
        for(auto& key : keys){
            auto curVal{ RegistryValue::Create(key, valueName) };
            if(!curVal){
                continue;
            }

            try{
                auto& regData{ ReadMultiValue(*curVal, GetPolicyName()) };
                auto& reqData{ std::get<std::vector<std::wstring>>(data) };
                for(auto& elem : regData){
                    bool found = false;
                    for(auto& present : reqData){
                        if(elem == present){
                            found = true;
                        }
                    }
                    if(!found){
                        return false;
                    }
                }
            } catch(std::exception& e){
                Bluespawn::io.InformUser(StringToWidestring(e.what()));
                return false;
            }
        }
        return true;
    } else {
        for(auto& key : keys){
            auto curVal{ RegistryValue::Create(key, valueName) };
            if(!curVal){
                continue;
            }

            try{
                auto& regData{ ReadMultiValue(*curVal, GetPolicyName()) };
                auto& reqData{ std::get<std::vector<std::wstring>>(data) };
                for(auto& elem : regData){
                    bool found = false;
                    for(auto& present : reqData){
                        if(elem == present){
                            found = true;
                        }
                    }
                    if(found){
                        return false;
                    }
                }
            } catch(std::exception& e){
                Bluespawn::io.InformUser(StringToWidestring(e.what()));
                return false;
            }
        }
        return true;
    }
}

SubkeyPolicy::SubkeyPolicy(const RegistryKey& key,
                           const std::vector<std::wstring>& subkeyNames,
                           SubkeyPolicyType policyType,
                           const std::wstring& name,
                           EnforcementLevel level,
                           const std::optional<std::wstring>& description,
                           const std::optional<Version>& min,
                           const std::optional<Version>& max) :
    RegistryPolicy(key, name, level, description, min, max),
    subkeyNames(subkeyNames.begin(), subkeyNames.end()), policyType{ policyType } {}

SubkeyPolicy::SubkeyPolicy(json policy) : RegistryPolicy(policy) {
    assert(policy.find("subkey-names") != policy.end());
    assert(policy.find("subkey-policy-type") != policy.end());

    auto typeString{ ToLowerCaseA(policy["subkey-policy-type"].get<std::string>()) };
    if(typeString == "blacklist") {
        policyType = SubkeyPolicyType::Blacklist;
    } else if(typeString == "whitelist") {
        policyType = SubkeyPolicyType::Whitelist;
    } else
        throw std::exception(("Unknown registry policy type: " + typeString).c_str());

    for(auto& entry : policy["subkey-names"]) {
        subkeyNames.emplace(StringToWidestring(entry.get<std::string>()));
    }
}

bool SubkeyPolicy::Enforce() {
    if(IsEnforced()) {
        if(!MatchesSystem()) {
            for(auto& key : keys){
                auto subkeys{ key.EnumerateSubkeyNames() };
                if(policyType == SubkeyPolicyType::Whitelist){
                    for(auto& subkey : subkeys){
                        if(subkeyNames.find(subkey) == subkeyNames.end()){
                            if(!key.DeleteSubkey(subkey)){
                                return false;
                            }
                        }
                    }
                } else{
                    for(auto& subkey : subkeys){
                        if(subkeyNames.find(subkey) != subkeyNames.end()){
                            if(!key.DeleteSubkey(subkey)){
                                return false;
                            }
                        }
                    }
                }
            }
            return true;
        } else
            return true;
    } else {
        return MatchesSystem();
    }
}

bool SubkeyPolicy::MatchesSystem() const {
    for(auto& key : keys){
        auto subkeys{ key.EnumerateSubkeyNames() };
        if(policyType == SubkeyPolicyType::Whitelist){
            for(auto& subkey : subkeys){
                if(subkeyNames.find(subkey) == subkeyNames.end()){
                    return false;
                }
            }
        } else{
            for(auto& subkey : subkeys){
                if(subkeyNames.find(subkey) != subkeyNames.end()){
                    return false;
                }
            }
        }
    }
    return true;
}
