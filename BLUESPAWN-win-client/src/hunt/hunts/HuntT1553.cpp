#include "hunt/hunts/HuntT1553.h"

#include <map>
#include <queue>
#include <vector>

#include "util/StringUtils.h"
#include "util/Utils.h"
#include "util/configurations/Registry.h"
#include "util/filesystem/Filesystem.h"
#include "util/log/Log.h"
#include "util/processes/ProcessUtils.h"

#include "../resources/resource.h"
#include "hunt/RegistryHunt.h"
#include "user/bluespawn.h"

using namespace Registry;

#define SIPS 0
#define PROVIDERS 1
#define SIGNED 2

namespace Hunts {

    HuntT1553::HuntT1553() : Hunt(L"T1553 - Subvert Trust Controls") {
        dwCategoriesAffected = (DWORD) Category::Configurations;
        dwSourcesInvolved = (DWORD) DataSource::Registry;
        dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::DefenseEvasion;
    }

    std::wstring GetResource(DWORD identifier) {
        auto hRsrcInfo = FindResourceW(nullptr, MAKEINTRESOURCE(identifier), L"textfile");
        if(!hRsrcInfo) {
            return { nullptr, 0 };
        }

        auto hRsrc = LoadResource(nullptr, hRsrcInfo);
        if(!hRsrc) {
            return { nullptr, 0 };
        }

        return StringToWidestring(
            { reinterpret_cast<LPCSTR>(LockResource(hRsrc)), SizeofResource(nullptr, hRsrcInfo) });
    }

    std::unordered_map<std::wstring, std::unordered_map<std::wstring, std::pair<std::wstring, std::wstring>>>
    ParseResource(DWORD dwResourceID) {
        auto resource{ GetResource(dwResourceID) };

        std::unordered_map<std::wstring, std::unordered_map<std::wstring, std::pair<std::wstring, std::wstring>>> map{};

        auto lines{ SplitStringW(resource, L"\n") };
        for(auto& line : lines) {
            std::unordered_map<std::wstring, std::pair<std::wstring, std::wstring>> values;
            auto type{ line.substr(0, line.find(L":")) };
            auto entries{ SplitStringW(line.substr(line.find(L":") + 1), L" ") };
            for(auto& entry : entries) {
                auto parts{ SplitStringW(entry, L",") };
                auto path{ FileSystem::SearchPathExecutable(parts[1]) };
                if(path) {
                    values.emplace(parts[0], std::pair<std::wstring, std::wstring>{ ToLowerCaseW(*path), parts[2] });
                } else {
                    values.emplace(parts[0], std::pair<std::wstring, std::wstring>{ ToLowerCaseW(parts[1]), parts[2] });
                }
            }
            map.emplace(type, std::move(values));
        }

        return map;
    }

    void HuntT1553::Subtechnique003(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        SUBTECHNIQUE_INIT(3, SIP and Trust Provider Hijacking);

        std::unordered_map<std::wstring, std::vector<std::pair<RegistryValue, std::wstring>>> files{};

        // Verify SIPs
        SUBSECTION_INIT(SIPS, Intensive);
        auto goodSIP{ ParseResource(GoodSIP) };
        for(auto keypath : { L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0",
                             L"SOFTWARE\\WoW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType 0" }) {
            RegistryKey key{ HKEY_LOCAL_MACHINE, keypath };
            for(auto subkey : key.EnumerateSubkeyNames()) {
                if(goodSIP.find(subkey) != goodSIP.end()) {
                    auto& entry{ goodSIP.at(subkey) };
                    RegistryKey SIPType{ key, subkey };

                    for(auto GUID : SIPType.EnumerateSubkeyNames()) {
                        RegistryKey GUIDInfo{ SIPType, GUID };
                        auto dll{ RegistryValue::Create(GUIDInfo, L"Dll") };
                        auto func{ RegistryValue::Create(GUIDInfo, L"FuncName") };
                        GUID = GUID.substr(1, GUID.length() - 2);

                        if(entry.find(GUID) != entry.end()) {
                            auto& pair{ entry.at(GUID) };
                            if(func && func->ToString() != pair.second) {
                                CREATE_DETECTION_WITH_CONTEXT(
                                    Certainty::Strong,
                                    RegistryDetectionData{ *func, RegistryDetectionType::Configuration },
                                    DetectionContext{ __name },
                                    [GUIDInfo, pair](){ GUIDInfo.SetValue(L"FuncName", pair.second); });
                            }

                            if(dll) {
                                if(files.find(dll->ToString()) == files.end()) {
                                    files.emplace(dll->ToString(),
                                                  std::vector<std::pair<RegistryValue, std::wstring>>{
                                                      std::pair<RegistryValue, std::wstring>{ *dll, pair.first } });
                                } else {
                                    files.at(dll->ToString())
                                        .emplace_back(std::pair<RegistryValue, std::wstring>{ *dll, pair.first });
                                }
                            }
                        } else {
                            auto message{ L"Nonstandard subject interface provider GUID " + GUID + L" (DLL: " +
                                          dll->ToString() + L", Function: " + func->ToString() + L")" };

                            if(func) {
                                CREATE_DETECTION_WITH_CONTEXT(
                                    Certainty::Strong,
                                    RegistryDetectionData{ *func, RegistryDetectionType::Configuration },
                                    DetectionContext{ __name, std::nullopt, message });
                            }

                            if(dll) {
                                CREATE_DETECTION_WITH_CONTEXT(
                                    Certainty::Strong,
                                    RegistryDetectionData{ *dll, RegistryDetectionType::FileReference },
                                    DetectionContext{ __name, std::nullopt, message });
                            }
                        }
                    }
                }
            }
        }
        SUBSECTION_END();

        // Verify trust providers
        SUBSECTION_INIT(PROVIDERS, Intensive);
        auto goodTrustProviders{ ParseResource(GoodTrustProviders) };
        for(auto keypath : { L"SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust",
                             L"SOFTWARE\\WoW6432Node\\Microsoft\\Cryptography\\Providers\\Trust" }) {
            RegistryKey key{ HKEY_LOCAL_MACHINE, keypath };
            for(auto& subkey : key.EnumerateSubkeyNames()) {
                if(goodTrustProviders.find(subkey) != goodTrustProviders.end()) {
                    auto& entry{ goodTrustProviders.at(subkey) };
                    RegistryKey ProviderType{ key, subkey };

                    for(auto& GUID : ProviderType.EnumerateSubkeyNames()) {
                        RegistryKey GUIDInfo{ ProviderType, GUID };
                        auto dll{ RegistryValue::Create(GUIDInfo, L"$DLL") };
                        auto func{ RegistryValue::Create(GUIDInfo, L"$Function") };
                        GUID = GUID.substr(1, GUID.length() - 2);

                        if(entry.find(GUID) != entry.end()) {
                            auto& pair{ entry.at(GUID) };
                            if(func && func->ToString() != pair.second) {
                                CREATE_DETECTION_WITH_CONTEXT(
                                    Certainty::Strong,
                                    RegistryDetectionData{ *func, RegistryDetectionType::Configuration },
                                    DetectionContext{ __name },
                                    [GUIDInfo, pair](){ GUIDInfo.SetValue(L"$Function", pair.second); });
                            }

                            if(files.find(dll->ToString()) == files.end()) {
                                files.emplace(dll->ToString(),
                                              std::vector<std::pair<RegistryValue, std::wstring>>{
                                                  std::pair<RegistryValue, std::wstring>{ *dll, pair.first } });
                            } else {
                                files.at(dll->ToString())
                                    .emplace_back(std::pair<RegistryValue, std::wstring>{ *dll, pair.first });
                            }
                        } else {
                            auto message{ L"Nonstandard trust provider GUID " + GUID + L" for " + subkey + L" (DLL: " +
                                          dll->ToString() + L", Function: " + func->ToString() + L")" };
                            if(func) {
                                CREATE_DETECTION_WITH_CONTEXT(
                                    Certainty::Strong,
                                    RegistryDetectionData{ *func, RegistryDetectionType::Configuration },
                                    DetectionContext{ __name, std::nullopt, message });
                            }

                            if(dll) {
                                CREATE_DETECTION_WITH_CONTEXT(
                                    Certainty::Strong,
                                    RegistryDetectionData{ *dll, RegistryDetectionType::FileReference },
                                    DetectionContext{ __name, std::nullopt, message });
                            }
                        }
                    }
                }
            }
        }
        SUBSECTION_END();

        // Verify collection of DLLs
        for(auto& pair : files) {
            auto dllpath{ FileSystem::SearchPathExecutable(pair.first) };
            if(!dllpath) {
                auto message{ L"DLL " + pair.first + L" not found and may be a target for hijacking" };

                // Assume the worst - if the DLL path isn't found, it's because there's a target process that WILL find it
                for(auto& value : pair.second) {
                    CREATE_DETECTION_WITH_CONTEXT(
                        Certainty::Weak, RegistryDetectionData{ value.first, RegistryDetectionType::FileReference },
                        DetectionContext{ __name, std::nullopt, message });
                }
            } else {
                dllpath = ToLowerCaseW(*dllpath);
                auto location{ dllpath->find(L"syswow64") };
                if(location != std::wstring::npos) {
                    dllpath->replace(dllpath->begin() + location, dllpath->begin() + location + 8, L"system32");
                }
                for(auto& value : pair.second) {
                    if(dllpath != value.second &&
                       (dllpath->length() >= value.second.length() &&
                        dllpath->substr(dllpath->length() - value.second.length()) != value.second)) {
                        auto message{ L"Path for dll " + *dllpath + L" does not match " + value.second +
                                      L" and may have been hijacked" };
                        CREATE_DETECTION_WITH_CONTEXT(
                            Certainty::Weak, RegistryDetectionData{ value.first, RegistryDetectionType::FileReference },
                            DetectionContext{ __name, std::nullopt, message });
                    }
                }
            }
        }

        // Ensure only Microsoft signed DLLs are used here
        SUBSECTION_INIT(SIGNED, Intensive);
        std::vector<std::wstring> keypaths{ L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0",
                                            L"SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust" };
        for(auto keypath : keypaths) {
            for(auto key : CheckSubkeys(HKEY_LOCAL_MACHINE, keypath, true, false)) {
                std::queue<RegistryKey> keys{};
                keys.emplace(key);

                while(keys.size()) {
                    auto check{ keys.front() };
                    keys.pop();

                    for(auto val : check.EnumerateValues()) {
                        auto type{ check.GetValueType(val) };
                        if(type == RegistryType::REG_SZ_T || type == RegistryType::REG_EXPAND_SZ_T) {
                            auto path{ FileSystem::SearchPathExecutable(*check.GetValue<std::wstring>(val)) };
                            if(path) {
                                if(!FileSystem::File(*path).IsMicrosoftSigned()) {
                                    CREATE_DETECTION(Certainty::Strong,
                                                     RegistryDetectionData{ *RegistryValue::Create(check, val),
                                                                            RegistryDetectionType::FileReference });
                                }
                            } else if(ToLowerCaseW(val).find(L"dll") != std::wstring::npos) {
                                CREATE_DETECTION(Certainty::Strong,
                                                 RegistryDetectionData{ *RegistryValue::Create(check, val),
                                                                        RegistryDetectionType::FileReference });
                            }
                        }
                    }
                    for(auto subkey : check.EnumerateSubkeys()) {
                        keys.emplace(subkey);
                    }
                }
            }
        }
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }

    std::vector<std::shared_ptr<Detection>> HuntT1553::RunHunt(const Scope& scope) {
        HUNT_INIT();

        Subtechnique003(scope, detections);

        HUNT_END();
    }

    std::vector<std::pair<std::unique_ptr<Event>, Scope>> HuntT1553::GetMonitoringEvents() {
        std::vector<std::pair<std::unique_ptr<Event>, Scope>> events;

        Registry::GetRegistryEvents(events, Scope::CreateSubhuntScope((1 << SIPS) | (1 << SIGNED)), HKEY_LOCAL_MACHINE,
                                    L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0", true, false, true);
        Registry::GetRegistryEvents(events, Scope::CreateSubhuntScope((1 << PROVIDERS) | (1 << SIGNED)),
                                    HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust", true,
                                    false, true);

        return events;
    }
}   // namespace Hunts
