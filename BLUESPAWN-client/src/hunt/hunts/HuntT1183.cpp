#include "hunt/hunts/HuntT1183.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"

#include "common/Utils.h"

using namespace Registry;

namespace Hunts{
	HuntT1183::HuntT1183() : Hunt(L"T1183 - Image File Execution Options") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
	}

	int HuntT1183::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO(L"Hunting for " << name << L" at level Cursory");
		reaction.BeginHunt(GET_INFO());

		std::vector<RegistryValue> values;

		auto IFEO = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" };
		for(auto subkey : IFEO.EnumerateSubkeys()){
			ADD_ALL_VECTOR(values, CheckValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", {
				{ L"Debugger", L"", false, CheckSzEmpty },
				{ L"GlobalFlag", 0, false, [](DWORD d1, DWORD d2){ return !(d1 & 0x200); } },
			}));
			auto GFlags = subkey.GetValue<DWORD>(L"GlobalFlag");
			if(GFlags && *GFlags & 0x200){
				auto name = subkey.GetName();
				name = name.substr(name.find_last_of(L"\\") + 1);
				ADD_ALL_VECTOR(values, CheckValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\" + name, {
					{ L"ReportingMode", 0, false, CheckDwordEqual },
					{ L"MonitorProcess", L"", false, CheckSzEmpty },
				}));
			}
		}

		int detections = 0;
		for(const auto& value : values){
			reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(value));
			detections++;
		}

		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1183::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		ADD_ALL_VECTOR(events, GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", true, false, true));
		ADD_ALL_VECTOR(events, GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", true, false, true));
		
		return events;
	}
}