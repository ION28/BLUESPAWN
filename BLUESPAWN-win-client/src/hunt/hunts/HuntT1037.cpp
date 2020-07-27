#include "hunt/hunts/HuntT1037.h"

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"

#include "hunt/RegistryHunt.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {
    HuntT1037::HuntT1037() : Hunt(L"T1037 - Logon Scripts") {
        dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
        dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
        dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::LateralMovement;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1037::RunHunt(const Scope& scope) {
        HUNT_INIT();

        for(auto& detection : CheckValues(HKEY_CURRENT_USER, L"Environment",
                                          { { L"UserInitMprLogonScript", L"", false, CheckSzEmpty } }, true, true)) {
            CREATE_DETECTION(Certainty::Strong,
                             RegistryDetectionData{ detection.key, detection, RegistryDetectionType::FileReference,
                                                    detection.key.GetRawValue(detection.wValueName) });
        }

        std::vector<FileSystem::Folder> startup_directories = { FileSystem::Folder(
            L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp") };
        auto userFolders = FileSystem::Folder{ L"C:\\Users" }.GetSubdirectories(1);
        for(auto userFolder : userFolders) {
            FileSystem::Folder folder{ userFolder.GetFolderPath() +
                L"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp" };
            if(folder.GetFolderExists()) {
                startup_directories.emplace_back(folder);
            }
        }
        for(auto folder : startup_directories) {
            LOG_VERBOSE(1, L"Scanning " << folder.GetFolderPath());
            for(auto value : folder.GetFiles(std::nullopt, -1)) {
                CREATE_DETECTION(Certainty::None, FileDetectionData{ value });
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1037::GetMonitoringEvents(){
        std::vector<std::unique_ptr<Event>> events;

        Registry::GetRegistryEvents(events, HKEY_CURRENT_USER, L"Environment", true, true, false);
        events.push_back(std::make_unique<FileEvent>(
            FileSystem::Folder{ L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp" }));

        auto userFolders = FileSystem::Folder(L"C:\\Users").GetSubdirectories(1);
        for(auto userFolder : userFolders) {
            FileSystem::Folder folder{ userFolder.GetFolderPath() + 
                L"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp" };
            if(folder.GetFolderExists()) {
                events.push_back(std::make_unique<FileEvent>(folder));
            }
        }

        return events;
    }
}   // namespace Hunts
