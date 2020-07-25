#include "hunt/hunts/HuntT1101.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include "hunt/RegistryHunt.h"
#include "scan/FileScanner.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {
    HuntT1101::HuntT1101() : Hunt(L"T1101 - Security Support Provider") {
        dwCategoriesAffected = (DWORD) Category::Configurations;
        dwSourcesInvolved = (DWORD) DataSource::Registry;
        dwTacticsUsed = (DWORD) Tactic::Persistence;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1101::RunHunt(const Scope& scope) {
        HUNT_INIT();

        RegistryKey lsa{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" };
        RegistryKey lsa2{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig" };

        for(auto& key : { lsa, lsa2 }) {
            auto packages{ key.GetValue<std::vector<std::wstring>>(L"Security Packages") };
            if(packages) {
                for(auto& package : *packages) {
                    if(package != L"\"\"") {
                        auto filepath = FileSystem::SearchPathExecutable(package + L".dll");

                        if(filepath && FileScanner::PerformQuickScan(*filepath)) {
                            // Can't use a macro since we need the shared_ptr of the detection
                            auto value{ Bluespawn::detections.AddDetection(
                                Detection{ RegistryDetectionData{
                                               RegistryValue{ key, L"Security Packages", std::move(package) },
                                               RegistryDetectionType::FileReference },
                                           DetectionContext{ GetName() } },
                                Certainty::Moderate) };
                            detections.emplace_back(value);

                            // Since the security package is missing the dll extension, the scanner may not find the
                            // associated file
                            auto file{ Bluespawn::detections.AddDetection(Detection{ FileDetectionData{ *filepath },
                                                                                     DetectionContext{ GetName() } },
                                                                          Certainty::Weak) };
                            detections.emplace_back(file);

                            // Define the association ourself
                            file->info.AddAssociation(value, Association::Certain);
                            value->info.AddAssociation(file, Association::Certain);
                        }
                    }
                }
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1101::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        events.push_back(std::make_unique<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\"
                                                                                          L"Control\\Lsa" }));
        events.push_back(std::make_unique<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\"
                                                                                          L"Control\\Lsa\\OSConfig" }));

        return events;
    }
}   // namespace Hunts
