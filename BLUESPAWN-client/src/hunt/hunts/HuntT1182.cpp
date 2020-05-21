#include "hunt/hunts/HuntT1182.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"

using namespace Registry;

namespace Hunts {
	HuntT1182::HuntT1182() : Hunt(L"T1182 - AppCert DLLs") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
	}

	int HuntT1182::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO(L"Hunting for " << name << L" at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = 0;

		for(auto& detection : CheckKeyValues(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls", false, false)){
			reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(detection));
			detections++;

			auto filepath = FileSystem::SearchPathExecutable(detection.ToString());
			if (filepath) {
				reaction.FileIdentified(std::make_shared<FILE_DETECTION>(FileSystem::File{ filepath.value() }));
				detections++;
			}
		}

		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1182::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls", false, false, false));

		return events;
	}
}