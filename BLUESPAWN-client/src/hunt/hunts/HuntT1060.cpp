#include "hunt/hunts/HuntT1060.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "util/filesystem/YaraScanner.h"
#include "util/processes/ProcessUtils.h"
#include "util/processes/CheckLolbin.h"

#include "common/Utils.h"

using namespace Registry;

namespace Hunts {
	HuntT1060::HuntT1060() : Hunt(L"T1060 - Registry Run Keys / Startup Folder") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
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

	int HuntT1060::EvaluateFile(const std::wstring& cmd, Reaction& reaction) {

		if(IsLolbinMalicious(cmd)){
			return true;
		} else{
			auto filepath = GetImagePathFromCommand(cmd);
			auto image{ FileSystem::File(filepath) };

			if(image.GetFileExists() && !image.GetFileSigned()){
				auto& yara = YaraScanner::GetInstance();
				YaraScanResult result{ yara.ScanFile(image) };

				reaction.FileIdentified(std::make_shared<FILE_DETECTION>(image));

				return true;
			}
		}

		return false;
	}

	int HuntT1060::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO(L"Hunting for " << name << L" at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = 0;
		
		for(auto& key : RunKeys){
			for (auto& detection : CheckKeyValues(HKEY_LOCAL_MACHINE, key)) {
				if (EvaluateFile(detection.ToString(), reaction)) {
					reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(detection));
				}
				detections++;
			}
			for (auto& sub : CheckSubkeys(HKEY_LOCAL_MACHINE, key)) {
				for (auto& detection : CheckKeyValues(HKEY_LOCAL_MACHINE, sub.GetNameWithoutHive())) {
					if (EvaluateFile(detection.ToString(), reaction)) {
						reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(detection));
					}
					detections++;
				}
			}
		}

		for (auto& detection : CheckValues(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", {
			{ L"load", L"", false, CheckSzEmpty },
			{ L"run", L"", false, CheckSzEmpty }
			})) {
			detections += EvaluateFile(detection.ToString(), reaction);
			reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(detection));
			detections++;
		}

		for (auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", {
			{ L"BootExecute", {L"autocheck autochk *"}, false, CheckMultiSzSubset }
			})) {
				reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(detection));
				detections++;
		}

		for(auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Command Processor", {
			{ L"AutoRun", L"", false, CheckSzEmpty }
		})){
			if (EvaluateFile(detection.ToString(), reaction)) {
				reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(detection));
			}
			detections++;
		}

		for(auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", {
			{ L"Startup", L"%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", false, CheckSzEqual }
		})){
			if (EvaluateFile(detection.ToString(), reaction)) {
				reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(detection));
			}
			detections++;
		}

		for(auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", {
			{ L"Common Startup", L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", false, CheckSzEqual }
		})){
			if (EvaluateFile(detection.ToString(), reaction)) {
				reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(detection));
			}
			detections++;
		}



		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1060::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		for(auto key : RunKeys){ 
			ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, key, true, true, true));
		}

		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true, true, false));
		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", true, false, false));
		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Command Processor", true, false, true));
		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"));
		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"))

		return events;
	}
}