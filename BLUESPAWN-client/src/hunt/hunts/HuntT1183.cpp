#include "hunt/hunts/HuntT1183.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"

using namespace Registry;

namespace Hunts{
	HuntT1183::HuntT1183(HuntRegister& record) : Hunt(record, L"T1183 - Image File Execution Options") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
	}

	int HuntT1183::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1183 - Image File Execution Options at level Cursory");
		reaction.BeginHunt(GET_INFO());

		std::map<RegistryKey, std::vector<RegistryValue>> keys;

		auto IFEO = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" };
		for(auto subkey : IFEO.EnumerateSubkeys()){
			keys.emplace(subkey, CheckValues(subkey, {
				{ L"Debugger", RegistryType::REG_SZ_T, L"", false, CheckSzEmpty },
				{ L"GlobalFlag", RegistryType::REG_DWORD_T, 0, false, [](DWORD d1, DWORD d2){ return !(d1 & 0x200); } },
			}));
			auto GFlags = subkey.GetValue<DWORD>(L"GlobalFlag");
			if(GFlags && *GFlags & 0x200){
				auto name = subkey.GetName();
				name = name.substr(name.find_last_of(L"\\") + 1);
				auto SilentProcessExit = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\" + name };
				keys.emplace(SilentProcessExit, CheckValues(SilentProcessExit, {
					{ L"ReportingMode", RegistryType::REG_DWORD_T, 0, false, CheckDwordEqual },
					{ L"MonitorProcess", RegistryType::REG_SZ_T, L"", false, CheckSzEmpty },
				}));
			}
		}

		auto IFEOWow64 = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" };
		for(auto subkey : IFEOWow64.EnumerateSubkeys()){
			keys.emplace(subkey, CheckValues(subkey, {
				{ L"Debugger", RegistryType::REG_SZ_T, L"", false, CheckSzEmpty },
				{ L"GlobalFlag", RegistryType::REG_DWORD_T, 0, false, [](DWORD d1, DWORD d2){ return !(d1 & 0x200); } },
				}));
			auto GFlags = subkey.GetValue<DWORD>(L"GlobalFlag");
			if(GFlags && *GFlags & 0x200){
				auto name = subkey.GetName();
				name = name.substr(name.find_last_of(L"\\") + 1);
				auto SilentProcessExit = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\" + name };
				keys.emplace(SilentProcessExit, CheckValues(SilentProcessExit, {
					{ L"ReportingMode", RegistryType::REG_DWORD_T, 0, false, CheckDwordEqual },
					{ L"MonitorProcess", RegistryType::REG_SZ_T, L"", false, CheckSzEmpty },
				}));
			}
		}

		int detections = 0;
		for(const auto& key : keys){
			for(const auto& value : key.second){
				reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(key.first.GetName(), value));
				detections++;
			}
		}

		reaction.EndHunt();
		return detections;
	}

}