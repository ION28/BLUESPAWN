#include "hunt/hunts/HuntT1484.h"

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"

#include "user/bluespawn.h"

namespace Hunts {

    HuntT1484::HuntT1484() : Hunt(L"T1484 - Group Policy Modification") {
        dwCategoriesAffected = (DWORD) Category::Files;
        dwSourcesInvolved = (DWORD) DataSource::FileSystem | (DWORD) DataSource::GPO;
        dwTacticsUsed = (DWORD) Tactic::DefenseEvasion;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1484::RunHunt(const Scope& scope) {
        HUNT_INIT();

        auto userFolders = FileSystem::Folder(L"C:\\Users").GetSubdirectories(1);
        for(auto userFolder : userFolders) {
            FileSystem::File ntuserman{ userFolder.GetFolderPath() + L"\\ntuser.man" };
            if(ntuserman.GetFileExists()) {
                CREATE_DETECTION(Certainty::Moderate, FileDetectionData{ ntuserman });
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1484::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        events.push_back(std::make_unique<FileEvent>(FileSystem::Folder(L"C:\\Users")));
        auto userFolders = FileSystem::Folder(L"C:\\Users").GetSubdirectories(1);
        for(auto userFolder : userFolders) {
            events.push_back(std::make_unique<FileEvent>(userFolder));
        }

        return events;
    }
}   // namespace Hunts
