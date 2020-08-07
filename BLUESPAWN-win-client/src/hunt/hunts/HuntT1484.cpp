#include "hunt/hunts/HuntT1484.h"

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"

#include "user/bluespawn.h"

#define NTUSER_MAN 0

namespace Hunts {

    HuntT1484::HuntT1484() : Hunt(L"T1484 - Group Policy Modification") {
        dwCategoriesAffected = (DWORD) Category::Files;
        dwSourcesInvolved = (DWORD) DataSource::FileSystem | (DWORD) DataSource::GPO;
        dwTacticsUsed = (DWORD) Tactic::DefenseEvasion;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1484::RunHunt(const Scope& scope) {
        HUNT_INIT();

        SUBSECTION_INIT(NTUSER_MAN, Normal)
        auto userFolders = FileSystem::Folder(L"C:\\Users").GetSubdirectories(1);
        for(auto userFolder : userFolders) {
            FileSystem::File ntuserman{ userFolder.GetFolderPath() + L"\\ntuser.man" };
            if(ntuserman.GetFileExists()) {
                CREATE_DETECTION(Certainty::Moderate, FileDetectionData{ ntuserman });
            }
        }
        SUBSECTION_END();

        HUNT_END();
    }

    std::vector<std::pair<std::unique_ptr<Event>, Scope>> HuntT1484::GetMonitoringEvents() {
        std::vector<std::pair<std::unique_ptr<Event>, Scope>> events;

        auto scope{ SCOPE(NTUSER_MAN) };
        events.push_back(std::make_pair(std::make_unique<FileEvent>(FileSystem::Folder(L"C:\\Users")), scope));
        auto userFolders = FileSystem::Folder(L"C:\\Users").GetSubdirectories(1);
        for(auto userFolder : userFolders) {
            events.push_back(std::make_pair(std::make_unique<FileEvent>(userFolder), scope));
        }

        return events;
    }
}   // namespace Hunts
