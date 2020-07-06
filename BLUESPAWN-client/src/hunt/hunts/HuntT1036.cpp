#include "hunt/hunts/HuntT1036.h"

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"

#include "scan/FileScanner.h"
#include "user/bluespawn.h"

namespace Hunts {

    HuntT1036::HuntT1036() : Hunt(L"T1036 - Masquerading") {
        dwCategoriesAffected = (DWORD) Category::Files;
        dwSourcesInvolved = (DWORD) DataSource::FileSystem;
        dwTacticsUsed = (DWORD) Tactic::DefenseEvasion;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1036::RunHunt(const Scope& scope) {
        HUNT_INIT();

        for(auto folder : writableFolders) {
            auto f = FileSystem::Folder(folder);
            if(f.GetFolderExists()) {
                LOG_INFO(2, L"Scanning " << f.GetFolderPath());
                for(auto value : f.GetFiles(std::nullopt, -1)) {
                    if(FileScanner::PerformQuickScan(value.GetFilePath())) {
                        CREATE_DETECTION(Certainty::Weak, FileDetectionData{ value });
                    }
                }
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1036::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        for(auto folder : writableFolders) {
            auto f = FileSystem::Folder(folder);
            if(f.GetFolderExists()) {
                events.push_back(std::make_unique<FileEvent>(f));
                for(auto subdir : f.GetSubdirectories(-1)) {
                    events.push_back(std::make_unique<FileEvent>(subdir));
                }
            }
        }

        return events;
    }
}   // namespace Hunts
