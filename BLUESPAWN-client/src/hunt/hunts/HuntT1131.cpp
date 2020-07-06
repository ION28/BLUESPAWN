#include "hunt/hunts/HuntT1131.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include "hunt/RegistryHunt.h"
#include "scan/FileScanner.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {
    HuntT1131::HuntT1131() : Hunt(L"T1131 - Authentication Package") {
        dwCategoriesAffected = (DWORD) Category::Configurations;
        dwSourcesInvolved = (DWORD) DataSource::Registry;
        dwTacticsUsed = (DWORD) Tactic::Persistence;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1131::RunHunt(const Scope& scope) {
        HUNT_INIT();

        // LSA Configuration
        auto lsa = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" };
        for(auto PackageGroup : { L"Authentication Packages", L"Notification Packages" }) {
            auto packages = lsa.GetValue<std::vector<std::wstring>>(PackageGroup);
            if(packages) {
                for(auto package : *packages) {
                    auto filepath = FileSystem::SearchPathExecutable(package + L".dll");

                    if(filepath && FileScanner::PerformQuickScan(*filepath)) {
                        // Can't use a macro since we need the shared_ptr of the detection
                        auto value{ Bluespawn::detections.AddDetection(
                            Detection{ RegistryDetectionData{ RegistryValue{ lsa, PackageGroup, std::move(package) },
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

                        // Define the association here since the scanner may not pick up on it
                        file->info.AddAssociation(value, Association::Certain);
                        value->info.AddAssociation(file, Association::Certain);
                    }
                }
            }
        }

        // LSA Extensions Configuration
        auto lsaext = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\LsaExtensionConfig" };
        for(auto subkeyName : lsaext.EnumerateSubkeyNames()) {
            if(subkeyName == L"Interfaces") {
                for(auto subkey : RegistryKey{ lsaext, L"Interfaces" }.EnumerateSubkeys()) {
                    auto ext{ RegistryValue::Create(subkey, L"Extension") };
                    if(ext && FileScanner::PerformQuickScan(ext->ToString())) {
                        CREATE_DETECTION(Certainty::Moderate,
                                         RegistryDetectionData{ *ext, RegistryDetectionType::FileReference });
                    }
                }
            } else {
                auto subkey = RegistryKey{ lsaext, subkeyName };
                auto exts = subkey.GetValue<std::vector<std::wstring>>(L"Extensions");
                if(exts) {
                    for(auto ext : *exts) {
                        if(FileScanner::PerformQuickScan(ext)) {
                            CREATE_DETECTION(
                                Certainty::Moderate,
                                RegistryDetectionData{ RegistryValue{ subkey, L"Extensions", std::move(ext) },
                                                       RegistryDetectionType::FileReference });
                        }
                    }
                }
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1131::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        events.push_back(std::make_unique<RegistryEvent>(
            RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" }));
        events.push_back(std::make_unique<RegistryEvent>(
            RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\LsaExtensionConfig" }));

        return events;
    }
}   // namespace Hunts
