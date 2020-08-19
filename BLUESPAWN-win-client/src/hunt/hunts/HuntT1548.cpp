#include "hunt/hunts/HuntT1548.h"

#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"

#include "util/eventlogs/EventLogs.h"
#include "util/processes/ProcessUtils.h"

#include "user/bluespawn.h"

#define FODHELPER 0
#define EVT_VIEWER_REGISTRY 1
#define SDCLT_REGISTRY 2

using namespace Registry;

namespace Hunts {
	HuntT1548::HuntT1548() : Hunt(L"T1548 - Abuse Elevation Control Mechanism") {
		dwCategoriesAffected = (DWORD)Category::Processes | (DWORD)Category::Configurations;
		dwSourcesInvolved = (DWORD)DataSource::Processes | (DWORD)DataSource::Registry;
		dwTacticsUsed = (DWORD)Tactic::PrivilegeEscalation | (DWORD)Tactic::DefenseEvasion;
	}

	void HuntT1548::Subtechnique002(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        SUBTECHNIQUE_INIT(002, Bypass User Access Control);

		SUBSECTION_INIT(FODHELPER, Cursory);

		// Reference: https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/
		// Test Commands:
		//		1. reg add "HKCU\SOFTWARE\Classes\ms-settings\shell\open\command" /v "DelegateExecute"
		//		2. reg add "HKCU\SOFTWARE\Classes\ms-settings\shell\open\command" /ve /t REG_SZ /d "cmd.exe" 
		RegistryKey msSettingsCommand{ HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\ms-settings\\shell\\open\\command" };
        if(msSettingsCommand.ValueExists(L"DelegateExecute")) {
            for(auto& detection :
                CheckValues(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\ms-settings\\shell\\open\\command",
                            { { DEFAULT, L"REG_SZ", false, CheckSzEmpty } }, true, true)) {
                CREATE_DETECTION(Certainty::Strong,
                                 RegistryDetectionData{ detection, RegistryDetectionType::CommandReference });
            }
        }

        SUBSECTION_END();

		// Reference: https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
		// Test Command: reg add "HKCU\SOFTWARE\Classes\mscfile\shell\open\command" /ve /t REG_SZ /d "cmd.exe" 
		// Metasploit module: https://www.exploit-db.com/exploits/40268
        SUBSECTION_INIT(EVT_VIEWER_REGISTRY, Cursory);

		for(RegistryValue& detection :
            CheckValues(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\mscfile\\shell\\open\\command",
                        { { DEFAULT, L"REG_SZ", false, CheckSzEmpty } }, false, false)) {
            CREATE_DETECTION(Certainty::Strong,
                             RegistryDetectionData{ detection, RegistryDetectionType::CommandReference });
        }

		SUBSECTION_END();

		// Reference: https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/
		// Test Command: reg add "HKCU\SOFTWARE\Classes\exefile\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe" 
		SUBSECTION_INIT(SDCLT_REGISTRY, Cursory);

        for(auto& detection : CheckValues(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\exefile\\shell\\runas\\command",
                                          { { L"IsolatedCommand", L"REG_SZ", false, CheckSzEmpty } }, true, true)) {
            CREATE_DETECTION(Certainty::Strong,
                             RegistryDetectionData{ detection, RegistryDetectionType::CommandReference });
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

        GetRegistryEvents(events, SCOPE(FODHELPER), HKEY_CURRENT_USER,
                          L"SOFTWARE\\Classes\\ms-settings\\shell\\open\\command", true, true, true);

        GetRegistryEvents(events, SCOPE(EVT_VIEWER_REGISTRY), HKEY_CURRENT_USER,
                          L"SOFTWARE\\Classes\\mscfile\\shell\\open\\command", true, true);

		GetRegistryEvents(events, SCOPE(SDCLT_REGISTRY), HKEY_CURRENT_USER,
                          L"SOFTWARE\\Classes\\exefile\\shell\\runas\\command", true, true);

		return events;
	}
}