#include "hunt/hunts/HuntT1101.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "util/filesystem/YaraScanner.h"

using namespace Registry;

namespace Hunts {
	HuntT1101::HuntT1101() : Hunt(L"T1101 - Security Support Provider") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1101::EvaluatePackages(Registry::RegistryKey key, std::vector<std::wstring> vSecPackages, Reaction reaction) {
		int detections = 0;

		FileSystem::File* file;

		for (auto secPackage : vSecPackages) {
			if (secPackage == L"\"\"") {
				continue;
			}
			if (FileSystem::File(secPackage).GetFileExists()) {
				file = new FileSystem::File(secPackage);
			}
			else {
				file = new FileSystem::File(ExpandEnvStringsW(L"%SYSTEMROOT%\\System32\\") + secPackage + L".dll");
				if (!file->GetFileExists()) { continue; }
			}

			auto& yara = YaraScanner::GetInstance();
			YaraScanResult result = yara.ScanFile(*file);

			if (!file->GetFileSigned()) {
				reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ key, L"Security Packages", *key.GetValue<std::vector<std::wstring>>(L"Security Packages")}));
				reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file->GetFilePath()));
				detections += 2;
			}
		}

		return detections;
	}

	int HuntT1101::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO(L"Hunting for " << name << " at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = 0;

		auto lsa = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" };
		auto vSecPackages = *lsa.GetValue<std::vector<std::wstring>>(L"Security Packages");
		detections += EvaluatePackages(lsa, vSecPackages, reaction);

		auto lsa2 = RegistryKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig");
		auto vSecPackages2 = *lsa2.GetValue<std::vector<std::wstring>>(L"Security Packages");
		detections += EvaluatePackages(lsa2, vSecPackages2, reaction);

		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1101::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		events.push_back(std::make_shared<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" }));
		events.push_back(std::make_shared<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig" }));

		return events;
	}
}