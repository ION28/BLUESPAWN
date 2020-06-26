#include "hunt/hunts/HuntT1060.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"

#include "common/Utils.h"

using namespace Registry;

namespace Hunts {
	HuntT1060::HuntT1060() : Hunt(L"T1060 - Registry Run Keys / Startup Folder") {
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;

		auto HKLMRun = std::wstring{ L"Software\\Microsoft\\Windows\\CurrentVersion\\Run" };
		auto HKLMRunServices = std::wstring{ L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" };
		auto HKLMRunOnce = std::wstring{ L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" };
		auto HKLMRunServicesOnce = std::wstring{ L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceServices" };
		auto HKLMRunOnceEx = std::wstring{ L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" };
		auto HKLMRunServicesOnceEx = std::wstring{ L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceServicesEx" };
		auto HKLMExplorerRun = std::wstring{ L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" };

		RunKeys = {
			HKLMRun, HKLMRunServices, HKLMRunOnce, HKLMRunServicesOnce, 
			HKLMRunOnceEx, HKLMRunServicesOnceEx, HKLMExplorerRun,
		};
	}

	std::vector<std::reference_wrapper<Detection>> HuntT1060::RunHunt(const Scope& scope){
		HUNT_INIT();
		
		for(auto& key : RunKeys){
			for(auto& detection : CheckKeyValues(HKEY_LOCAL_MACHINE, key)){
				REGISTRY_DETECTION(detection);
			}
		}

		for(auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Command Processor", {
			{ L"AutoRun", L"", false, CheckSzEmpty }
		})){
			REGISTRY_DETECTION(detection);
		}

		for(auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", {
			{ L"Startup", L"%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", false, CheckSzEqual }
		})){
			REGISTRY_DETECTION(detection);
		}

		for(auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", {
			{ L"Common Startup", L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", false, CheckSzEqual }
		})){
			REGISTRY_DETECTION(detection);
		}

		HUNT_END();
	}

	std::vector<std::unique_ptr<Event>> HuntT1060::GetMonitoringEvents() {
		std::vector<std::unique_ptr<Event>> events;

		for(auto key : RunKeys){ 
			Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE, key);
		}

		Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Command Processor");
		Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders");
		Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders")

		return events;
	}
}