#include "hunt/hunts/HuntT1548.h"

#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"

#include "util/eventlogs/EventLogs.h"
#include "util/processes/ProcessUtils.h"

#include "user/bluespawn.h"

#define EVT_VIEWER_REGISTRY 0
#define SDCLT_REGISTRY 1

using namespace Registry;

namespace Hunts {
	HuntT1548::HuntT1548() : Hunt(L"T1548 - Abuse Elevation Control Mechanism") {
		dwCategoriesAffected = (DWORD)Category::Processes | (DWORD)Category::Configurations;
		dwSourcesInvolved = (DWORD)DataSource::Processes | (DWORD)DataSource::Registry;
		dwTacticsUsed = (DWORD)Tactic::PrivilegeEscalation | (DWORD)Tactic::DefenseEvasion;
	}

	void HuntT1548::Subtechnique002(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
		SUBTECHNIQUE_INIT(002, Abuse Elevation Control Mechanism);

		// Reference: https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
		SUBSECTION_INIT(EVT_VIEWER_REGISTRY, Normal);

		RegistryKey mscfileCommand = RegistryKey(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\mscfile\\shell\\open\\command");
		std::optional<RegistryValue> cmd = RegistryValue::Create(mscfileCommand, DEFAULT);
		if (cmd) {
			CREATE_DETECTION(Certainty::Certain,
				RegistryDetectionData{ *cmd, RegistryDetectionType::CommandReference });
		}

		SUBSECTION_END();

		// Reference: https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/
		SUBSECTION_INIT(SDCLT_REGISTRY, Normal);

		RegistryKey exefileCommand = RegistryKey(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\exefile\\shell\\runas\\command");
		std::optional<RegistryValue> cmd = RegistryValue::Create(exefileCommand, L"IsolatedCommand");
		if (cmd) {
			CREATE_DETECTION(Certainty::Certain,
				RegistryDetectionData{ *cmd, RegistryDetectionType::CommandReference });
		}
		SUBSECTION_END();

		SUBTECHNIQUE_END();
	}
	std::vector<std::shared_ptr<Detection>> HuntT1548::RunHunt(const Scope& scope)
	{
		HUNT_INIT();

		Subtechnique002(scope, detections);

		HUNT_END();
	}
	std::vector<std::pair<std::unique_ptr<Event>, Scope>> HuntT1548::GetMonitoringEvents()
	{
		std::vector<std::pair<std::unique_ptr<Event>, Scope>> events;

		GetRegistryEvents(events, SCOPE(EVT_VIEWER_REGISTRY), HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\mscfile\\shell\\open\\command",
			false, false);

		GetRegistryEvents(events, SCOPE(SDCLT_REGISTRY), HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\exefile\\shell\\runas\\command",
			false, false);

		return events;
	}
}