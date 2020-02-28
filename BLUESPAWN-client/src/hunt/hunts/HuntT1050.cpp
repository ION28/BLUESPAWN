#include "hunt/hunts/HuntT1050.h"
#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"
#include "util/log/HuntLogMessage.h"
#include <util\filesystem\YaraScanner.h>

#include <iostream>

namespace Hunts {

	HuntT1050::HuntT1050() : Hunt(L"T1050 - New Service") {
		// TODO: update these categories
		dwSupportedScans = (DWORD) Aggressiveness::Normal | (DWORD) Aggressiveness::Intensive;
		dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
		dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	std::vector<EventLogs::EventLogItem> HuntT1050::Get7045Events() {
		// Create existance queries so interesting data is output
		std::vector<EventLogs::XpathQuery> queries;
		auto param1 = EventLogs::ParamList();
		auto param2 = EventLogs::ParamList();
		auto param3 = EventLogs::ParamList();
		auto param4 = EventLogs::ParamList();
		param1.push_back(std::make_pair(L"Name", L"'ServiceName'"));
		param2.push_back(std::make_pair(L"Name", L"'ImagePath'"));
		param3.push_back(std::make_pair(L"Name", L"'ServiceType'"));
		param4.push_back(std::make_pair(L"Name", L"'StartType'"));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param1));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param2));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param3));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param4));

		auto queryResults = EventLogs::QueryEvents(L"System", 7045, queries);

		return queryResults;
	}

	int HuntT1050::ScanNormal(const Scope& scope, Reaction reaction) {
		LOG_INFO(L"Hunting for " << name << L" at level Normal");
		reaction.BeginHunt(GET_INFO());

		auto queryResults = Get7045Events();

		auto& yara = YaraScanner::GetInstance();
		int detections = 0;

		
		for (auto result : queryResults) {
			auto imageName = result.GetProperty(L"Event/EventData/Data[@Name='ServiceName']");
			auto imagePath = result.GetProperty(L"Event/EventData/Data[@Name='ImagePath']");

			// Find detections with YARA rules
			FileSystem::File file = FileSystem::File(imagePath);
			YaraScanResult ScanResult = yara.ScanFile(file);

			if (!ScanResult && ScanResult.vKnownBadRules.size() > 0) {
				detections++;
				reaction.EventIdentified(EventLogs::EventLogItemToDetection(result));
				reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file.GetFilePath()));
			}

			// Look for PSExec services
			if (imageName.find(L"PSEXESVC") != std::wstring::npos) {
				reaction.EventIdentified(EventLogs::EventLogItemToDetection(result));
				detections++;
			}
			
			// Look for Mimikatz Driver loading
			if (imageName.find(L"mimikatz") != std::wstring::npos || imageName.find(L"mimidrv") != std::wstring::npos 
				|| imagePath.find(L"mimidrv.sys") != std::wstring::npos) {
				reaction.EventIdentified(EventLogs::EventLogItemToDetection(result));
				reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file.GetFilePath()));
				detections++;
			}

			// Calculate entropy of service names to look for suspicious services like 
			// the ones MSF generates https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/
			if (GetShannonEntropy(imageName) < 3.00 || GetShannonEntropy(imageName) > 5.00) {
				reaction.EventIdentified(EventLogs::EventLogItemToDetection(result));
				detections++;
			}
		}

		reaction.EndHunt();
		return detections;
	}

	int HuntT1050::ScanIntensive(const Scope& scope, Reaction reaction){
		LOG_INFO(L"Hunting for " << name << L" at level Intensive");
		reaction.BeginHunt(GET_INFO());


		auto queryResults = Get7045Events();

		auto& yara = YaraScanner::GetInstance();

		for (auto result : queryResults) {
			reaction.EventIdentified(EventLogs::EventLogItemToDetection(result));

			auto imagePath = result.GetProperty(L"Event/EventData/Data[@Name='ImagePath']");

			FileSystem::File file = FileSystem::File(imagePath);
			YaraScanResult ScanResult = yara.ScanFile(file);

			if (!ScanResult && ScanResult.vKnownBadRules.size() > 0) {
				reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file.GetFilePath()));
			}
		}

		reaction.EndHunt();
		return queryResults.size();
	}

	std::vector<std::shared_ptr<Event>> HuntT1050::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;
		events.push_back(std::make_shared<EventLogEvent>(L"System", 7045));
		events.push_back(std::make_shared<RegistryEvent>(Registry::RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services" }));

		return events;
	}

}