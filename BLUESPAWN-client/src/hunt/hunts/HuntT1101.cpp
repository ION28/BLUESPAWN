#include "hunt/hunts/HuntT1101.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include "hunt/RegistryHunt.h"
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

		auto lsa = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" };
		auto lsa2 = RegistryKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig");

		for (auto key : { lsa, lsa2 }) {
			auto Packages = key.GetValue<std::vector<std::wstring>>(L"Security Packages");
			if (Packages) {
				for (auto Package : Packages.value()) {
					if (Package != L"\"\"") {
						auto filepath = FileSystem::SearchPathExecutable(Package + L".dll");

						if (filepath) {
							FileSystem::File file = FileSystem::File(filepath.value());
							if (file.GetFileExists() && !file.GetFileSigned()) {
								reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ key, L"Security Packages", key.GetValue<std::vector<std::wstring>>(L"Security Packages").value() }));
								reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file));
								detections += 2;
							}
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
