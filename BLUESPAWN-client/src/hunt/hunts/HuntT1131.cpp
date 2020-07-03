#include "hunt/hunts/HuntT1131.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include "hunt/RegistryHunt.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {
	HuntT1131::HuntT1131() : Hunt(L"T1131 - Authentication Package") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1131::ScanCursory(const Scope& scope, Reaction reaction) {
		LOG_INFO(L"Hunting for " << name << L" at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = 0;

		// LSA Configuration
		auto lsa = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" };

		for (auto PackageGroup : { L"Authentication Packages", L"Notification Packages" }) {
			auto Packages = lsa.GetValue<std::vector<std::wstring>>(PackageGroup);
			if (Packages) {
				for (auto Package : Packages.value()) {
					if (Package != L"\"\"") {
						auto filepath = FileSystem::SearchPathExecutable(Package + L".dll");

						if (filepath) {
							FileSystem::File file = FileSystem::File(filepath.value());
							if (file.GetFileExists() && !file.GetFileSigned()) {
								reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ lsa, PackageGroup, lsa.GetValue<std::vector<std::wstring>>(PackageGroup).value() }));
								reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file));
								detections += 2;
							}
						}
					}
				}
			}
		}

		// LSA Extensions Configuration
		auto lsaext = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\LsaExtensionConfig" };

		for (auto subkeyName : lsaext.EnumerateSubkeyNames()) {
			if (subkeyName == L"Interfaces") {
				for (auto subkey : RegistryKey{ lsaext, L"Interfaces" }.EnumerateSubkeys()) {
					auto ext = subkey.GetValue<std::wstring>(L"Extension");
					if (ext) {
						auto filepath = FileSystem::SearchPathExecutable(ext.value());
						if (filepath) {
							FileSystem::File file = FileSystem::File(filepath.value());
							if (file.GetFileExists() && !file.GetFileSigned()) {
								reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ subkey, L"Extension", subkey.GetValue<std::wstring>(L"Extension").value() }));
								reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file));
								detections += 2;
							}
						}
					}
				}
			}
			else {
				auto subkey = RegistryKey{ lsaext, subkeyName };
				auto exts = subkey.GetValue<std::vector<std::wstring>>(L"Extensions");
				if (exts) {
					for (auto ext : exts.value()) {
						auto filepath = FileSystem::SearchPathExecutable(ext);
						if (filepath) {
							FileSystem::File file = FileSystem::File(filepath.value());
							if (file.GetFileExists() && !file.GetFileSigned()) {
								reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ subkey, L"Extensions", subkey.GetValue<std::wstring>(L"Extensions").value() }));
								reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file));
								detections += 2;
							}
						}
					}
				}
			}
		}


		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1131::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		events.push_back(std::make_unique<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" }));
		events.push_back(std::make_unique<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\LsaExtensionConfig" }));

		return events;
	}
}
