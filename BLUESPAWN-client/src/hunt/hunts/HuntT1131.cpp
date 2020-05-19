#include "hunt/hunts/HuntT1131.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "util/filesystem/YaraScanner.h"
#include "common/StringUtils.h"

using namespace Registry;

namespace Hunts {
	HuntT1131::HuntT1131() : Hunt(L"T1131 - Authentication Package") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1131::EvaluatePackages(Registry::RegistryKey key, std::vector<std::wstring> vPackages, std::wstring name, Reaction reaction) {
		int detections = 0;

		FileSystem::File* file;

		for (auto package : vPackages) {
			if (package == L"\"\"") {
				continue;
			}
			if (FileSystem::File(package).GetFileExists()) {
				file = new FileSystem::File(package);
			}
			else {
				file = new FileSystem::File(ExpandEnvStringsW(L"%SYSTEMROOT%\\System32\\") + package + L".dll");
				if (!file->GetFileExists()) { continue; }
			}

			auto& yara = YaraScanner::GetInstance();
			YaraScanResult result = yara.ScanFile(*file);

			if (!file->GetFileSigned()) {
				reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ key, name, key.GetValue<std::vector<std::wstring>>(name).value() }));
				reaction.FileIdentified(std::make_shared<FILE_DETECTION>(*file));
				detections += 2;
			}
		}

		return detections;
	}

	int HuntT1131::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO(L"Hunting for " << name << L" at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = 0;

		auto lsa = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" };
		auto AuthPackages = lsa.GetValue<std::vector<std::wstring>>(L"Authentication Packages").value();
		auto NotifPackages = lsa.GetValue<std::vector<std::wstring>>(L"Notification Packages").value();

		for (const auto& PackageGroup : { AuthPackages, NotifPackages }) {
			std::wstring k = L"lima";
			SplitStringW(k, L" ");
		}

		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1131::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", false, false, true));

		return events;
	}
}