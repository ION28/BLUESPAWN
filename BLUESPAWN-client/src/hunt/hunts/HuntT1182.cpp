#include "hunt/hunts/HuntT1182.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1182::HuntT1182() : Hunt(L"T1182 - AppCert DLLs") {
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
	}

	std::vector<std::shared_ptr<DETECTION>> HuntT1182::RunHunt(const Scope& scope){
		HUNT_INIT();

		for(auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager", {
			{ L"AppCertDLLs", std::vector<std::wstring>{}, false, CheckMultiSzEmpty },
		})){
			REGISTRY_DETECTION(detection);
		}

		HUNT_END();
	}

	std::vector<std::shared_ptr<Event>> HuntT1182::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		events.push_back(std::make_shared<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager" }));

		return events;
	}
}