#include "hunt/hunts/HuntT1122.h"

#include <algorithm>

#include "common/StringUtils.h"
#include "common/Utils.h"

#include "util/configurations/Registry.h"
#include "util/filesystem/Filesystem.h"
#include "util/log/Log.h"
#include "util/processes/CheckLolbin.h"
#include "util/processes/ProcessUtils.h"

#include "hunt/RegistryHunt.h"
#include "scan/FileScanner.h"
#include "scan/ProcessScanner.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {

    HuntT1122::HuntT1122() : Hunt(L"T1122 - COM Hijacking") {
        dwCategoriesAffected = (DWORD) Category::Configurations;
        dwSourcesInvolved = (DWORD) DataSource::Registry;
        dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::DefenseEvasion;
    }

#define ADD_FILE(file, ...)                                             \
    if(files.find(file) != files.end()) {                               \
        files.at(file).emplace_back(__VA_ARGS__);                       \
    } else {                                                            \
        files.emplace(file, std::vector<RegistryValue>{ __VA_ARGS__ }); \
    }

    std::vector<std::shared_ptr<Detection>> HuntT1122::RunHunt(const Scope& scope) {
        HUNT_INIT_LEVEL(Intensive);

        std::map<std::wstring, std::vector<RegistryValue>> files{};

        for(auto key : CheckSubkeys(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID", true, true)) {
            RegistryKey subkey{ key, L"InprocServer32" };
            if(subkey.Exists() && subkey.ValueExists(L"")) {
                auto filename{ *subkey.GetValue<std::wstring>(L"") };
                auto path{ FileSystem::SearchPathExecutable(filename) };
                if(path) {
                    ADD_FILE(*path, RegistryValue{ subkey, L"", std::move(filename) });
                }
            }
            subkey = { key, L"InprocServer" };
            if(subkey.Exists() && subkey.ValueExists(L"")) {
                auto filename{ *subkey.GetValue<std::wstring>(L"") };
                auto path{ FileSystem::SearchPathExecutable(filename) };
                if(path) {
                    ADD_FILE(*path, RegistryValue{ subkey, L"", std::move(filename) });
                }
            }
            if(key.ValueExists(L"InprocHandler32")) {
                auto filename{ *key.GetValue<std::wstring>(L"InprocHandler32") };
                auto path{ FileSystem::SearchPathExecutable(filename) };
                if(path) {
                    ADD_FILE(*path, RegistryValue{ key, L"InprocHandler32", std::move(filename) });
                }
            }
            if(key.ValueExists(L"InprocHandler")) {
                auto filename{ *key.GetValue<std::wstring>(L"InprocHandler") };
                auto path{ FileSystem::SearchPathExecutable(filename) };
                if(path) {
                    ADD_FILE(*path, RegistryValue{ key, L"InprocHandler", std::move(filename) });
                }
            }
            if(key.ValueExists(L"LocalServer")) {
                auto filename{ *key.GetValue<std::wstring>(L"LocalServer") };
                ADD_FILE(filename, RegistryValue{ key, L"LocalServer", *subkey.GetValue<std::wstring>(L"") });
            }
            subkey = { key, L"LocalServer32" };
            if(subkey.Exists() && subkey.ValueExists(L"")) {
                auto filename{ *subkey.GetValue<std::wstring>(L"") };
                ADD_FILE(filename, RegistryValue{ subkey, L"", *subkey.GetValue<std::wstring>(L"") });
            }
            if(subkey.Exists() && subkey.ValueExists(L"ServerExecutable")) {
                auto filename{ *subkey.GetValue<std::wstring>(L"ServerExecutable") };
                ADD_FILE(filename, RegistryValue{ subkey, L"ServerExecutable", *subkey.GetValue<std::wstring>(L"") });
            }
        }

        for(auto pair : files) {
            auto path{ pair.first };
            if(!FileSystem::CheckFileExists(path)) {
                path = GetImagePathFromCommand(path);
                if(!FileSystem::CheckFileExists(path)) {
                    continue;
                }
            }

            auto dll{ path.find(L".dll") != std::wstring::npos };
            if((dll && FileScanner::PerformQuickScan(path)) || (!dll && ProcessScanner::PerformQuickScan(pair.first))) {
                for(auto& value : pair.second) {
                    CREATE_DETECTION(Certainty::Moderate,
                                     RegistryDetectionData{ value, dll ? RegistryDetectionType::FileReference :
                                                                         RegistryDetectionType::CommandReference });
                }
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1122::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID", true, true, true);

        return events;
    }
}   // namespace Hunts
