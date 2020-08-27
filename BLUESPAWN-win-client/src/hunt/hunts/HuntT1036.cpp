#include "hunt/hunts/HuntT1036.h"

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"

#include "scan/FileScanner.h"
#include "user/bluespawn.h"

#define SEARCH_WRITABLE 0

namespace Hunts {

    HuntT1036::HuntT1036() : Hunt(L"T1036 - Masquerading") {
        dwCategoriesAffected = (DWORD) Category::Files;
        dwSourcesInvolved = (DWORD) DataSource::FileSystem;
        dwTacticsUsed = (DWORD) Tactic::DefenseEvasion;
    }

    void HuntT1036::Subtechnique005(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        SUBTECHNIQUE_INIT(005, Match Legitimate Name or Location);

        SUBSECTION_INIT(SEARCH_WRITABLE, Intensive);
        for(auto folder : writableFolders) {
            auto f = FileSystem::Folder(folder);
            if(f.GetFolderExists()) {
                LOG_INFO(2, L"Scanning " << f.GetFolderPath());
                for(auto value : f.GetFiles(std::nullopt, -1)) {
                    if(FileScanner::PerformQuickScan(value.GetFilePath())) {
                        CREATE_DETECTION(Certainty::None, FileDetectionData{ value });
                    }
                }
            }
        }
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }

    std::vector<std::shared_ptr<Detection>> HuntT1036::RunHunt(const Scope& scope) {
        HUNT_INIT();

        Subtechnique005(scope, detections);

        HUNT_END();
    }

    std::vector<std::pair<std::unique_ptr<Event>, Scope>> HuntT1036::GetMonitoringEvents() {
        std::vector<std::pair<std::unique_ptr<Event>, Scope>> events;

        if(Bluespawn::aggressiveness >= Aggressiveness::Intensive) {
            Scope scope{ Scope::CreateSubhuntScope(1 << SEARCH_WRITABLE) };
            for(auto folder : writableFolders) {
                auto f = FileSystem::Folder(folder);
                if(f.GetFolderExists()) {
                    events.push_back(std::make_pair(std::make_unique<FileEvent>(f), scope));
                    for(auto subdir : f.GetSubdirectories(-1)) {
                        events.push_back(std::make_pair(std::make_unique<FileEvent>(subdir), scope));
                    }
                }
            }
        }

        return events;
    }
}   // namespace Hunts
