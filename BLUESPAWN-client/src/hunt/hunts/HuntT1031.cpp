#include "hunt/hunts/HuntT1031.h"

#include "util/filesystem/FileSystem.h"
#include "util/configurations/Registry.h"
#include "hunt/RegistryHunt.h"
#include "util/filesystem/YaraScanner.h"
#include "util/processes/ProcessUtils.h"

#include "util/log/Log.h"

using namespace Registry;

namespace Hunts {

	HuntT1031::HuntT1031() : Hunt(L"T1031 - Modify Existing Service") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
		dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::Services;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1031::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for " << name << " at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = 0;

		// DNS Service Audit

		if (RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\DNS\\Parameters" }.Exists()) {
			std::vector<RegistryValue> dnsServerPlugins{ CheckValues(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\DNS\\Parameters", {
				{ L"ServerLevelPluginDll", L"", false, CheckSzEmpty },
			}, false, false) };

			for (auto& detection : dnsServerPlugins) {
				reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(detection));
				reaction.FileIdentified(std::make_shared<FILE_DETECTION>(FileSystem::File(detection.ToString())));
				detections += 2;
			}
		}


		// NTDS Service Audit
		if (RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\NTDS" }.Exists()) {
			std::vector<RegistryValue> lsassDlls{ CheckValues(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\NTDS", {
				{ L"LsaDbExtPt", L"", false, CheckSzEmpty },
				{ L"DirectoryServiceExtPt", L"", false, CheckSzEmpty },
			}, false, false) };

			for (auto& detection : lsassDlls) {
				auto file = FileSystem::File{ detection.ToString() };
				if (file.GetFileExists() && !file.GetFileSigned()) {
					reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(detection));
					reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file));
					detections += 2;
				}
			}
		}


		// Winsock2 Service Audit

		auto winsock2 = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters" };
		
		for (auto paramdll : { L"AutodialDLL", L"NameSpace_Callout" }) {
			auto filepath = winsock2.GetValue<std::wstring>(paramdll);
			if (filepath) {
				auto file = FileSystem::File{ filepath.value() };
				if (file.GetFileExists() && !file.GetFileSigned()) {
					reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ winsock2, paramdll, winsock2.GetValue<std::wstring>(paramdll).value() }));
					reaction.FileIdentified(std::make_shared<FILE_DETECTION>(FileSystem::File(file)));
					detections += 2;
				}
			}
		}

		auto appids = RegistryKey{ winsock2, L"AppId_Catalog" };

		if (appids.Exists()) {
			for (auto subkey : appids.EnumerateSubkeys()) {
				auto filepath = subkey.GetValue<std::wstring>(L"AppFullPath");
				if (filepath) {
					auto file = FileSystem::File{ filepath.value() };
					if (file.GetFileExists() && !file.GetFileSigned()) {
						reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ subkey, L"AppFullPath", subkey.GetValue<std::wstring>(L"AppFullPath").value() }));
						reaction.FileIdentified(std::make_shared<FILE_DETECTION>(FileSystem::File(file)));
						detections += 2;
					}
				}
			}
		}

		auto currentCallout = winsock2.GetValue<std::wstring>(L"Current_NameSpace_Catalog");
		if (currentCallout) {
			auto namespaceCatalog = RegistryKey{ winsock2, currentCallout.value() + L"\\Catalog_Entries" };
			auto namespaceCatalog64 = RegistryKey{ winsock2, currentCallout.value() + L"\\Catalog_Entries64" };
			for (auto subkey : { namespaceCatalog, namespaceCatalog64 }) {
				for (auto entry : subkey.EnumerateSubkeys()) {
					auto filepath = entry.GetValue<std::wstring>(L"LibraryPath");
					if (filepath) {
						auto file = FileSystem::File{ filepath.value() };
						if (file.GetFileExists() && !file.GetFileSigned()) {
							reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ entry, L"LibraryPath", entry.GetValue<std::wstring>(L"LibraryPath").value() }));
							reaction.FileIdentified(std::make_shared<FILE_DETECTION>(FileSystem::File(file)));
							detections += 2;
						}
					}
				}
			}
		}


		// Service Failure Audit

		auto services = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services" };

		for (auto service : services.EnumerateSubkeys()) {
			if (!service.ValueExists(L"FailureCommand")) {
				continue;
			}
			auto filepath = GetImagePathFromCommand(service.GetValue<std::wstring>(L"FailureCommand").value());

			for (std::wstring val : vSuspicious) {
				if (filepath.find(val) != std::wstring::npos) {
					reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ service, L"FailureCommand", service.GetValue<std::wstring>(L"FailureCommand").value() }));
					detections++;
					continue;
				}
			}

			if (!FileSystem::CheckFileExists(filepath)) {
				continue;
			}
			FileSystem::File image = FileSystem::File(filepath);

			if (!image.GetFileSigned()) {
				reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ service, L"FailureCommand", service.GetValue<std::wstring>(L"FailureCommand").value() }));

				auto& yara = YaraScanner::GetInstance();
				YaraScanResult result = yara.ScanFile(image);

				reaction.FileIdentified(std::make_shared<FILE_DETECTION>(image));

				detections += 2;
			}
		}

		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1031::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", false, false));
		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\DNS\\Parameters", false, false, false));
		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters", false, false, true));

		return events;
	}
}