#include "hunt/hunts/HuntT1099.h"
#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"
#include "util/log/HuntLogMessage.h"
#include <util\filesystem\YaraScanner.h>

#include <iostream>

namespace Hunts {

	HuntT1099::HuntT1099() : Hunt(L"T1099 - Timestomp") {
		dwSupportedScans = (DWORD) Aggressiveness::Normal;
		dwCategoriesAffected = (DWORD) Category::Files | (DWORD)Category::Processes;
		dwSourcesInvolved = (DWORD) DataSource::EventLogs;
		dwTacticsUsed = (DWORD) Tactic::DefenseEvasion;
	}

	int HuntT1099::ScanNormal(const Scope& scope, Reaction reaction) {
		LOG_INFO("Hunting for " << name << " at level Normal");
		reaction.BeginHunt(GET_INFO());

		// Create existance queries so interesting data is output
		std::vector<EventLogs::XpathQuery> queries;
		auto param1 = EventLogs::ParamList();
		auto param2 = EventLogs::ParamList();
		auto param3 = EventLogs::ParamList();
		auto param4 = EventLogs::ParamList();
		auto param5 = EventLogs::ParamList();
		param1.push_back(std::make_pair(L"Name", L"'Image'"));
		param2.push_back(std::make_pair(L"Name", L"'ProcessId'"));
		param3.push_back(std::make_pair(L"Name", L"'TargetFilename'"));
		param4.push_back(std::make_pair(L"Name", L"'CreationUtcTime'"));
		param5.push_back(std::make_pair(L"Name", L"'PreviousCreationUtcTime'"));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param1));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param2));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param3));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param4));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param5));

		auto queryResults = EventLogs::QueryEvents(L"Microsoft-Windows-Sysmon/Operational", 2, queries);

		auto& yara = YaraScanner::GetInstance();
		int detections = 0;

		// Find detections with YARA rules
		for (auto query : queryResults) {
			//TODO: Also scan ProcessId with PE-Sieve to see if malicious
			FileSystem::File file = FileSystem::File(query.GetProperty(L"Event/EventData/Data[@Name='TargetFilename']"));
			YaraScanResult result = yara.ScanFile(file);

			if (!result) {
				if (result.vKnownBadRules.size() > 0) {
					detections++;
					reaction.EventIdentified(EventLogs::EventLogItemToDetection(query));
					reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file.GetFilePath()));
				}
				for (auto identifier : result.vKnownBadRules) {
					LOG_INFO(file.GetFilePath() << L" matches known malicious identifier " << identifier);
				}
				for (auto identifier : result.vIndicatorRules) {
					LOG_INFO(file.GetFilePath() << L" matches known indicator identifier " << identifier);
				}
			}
		}

		reaction.EndHunt();
		return detections;
	}

	int HuntT1099::ScanIntensive(const Scope& scope, Reaction reaction) {
		LOG_INFO("Hunting for " << name << " at level Intensive");
		reaction.BeginHunt(GET_INFO());

		// Create existance queries so interesting data is output
		std::vector<EventLogs::XpathQuery> queries;
		auto param1 = EventLogs::ParamList();
		auto param2 = EventLogs::ParamList();
		auto param3 = EventLogs::ParamList();
		auto param4 = EventLogs::ParamList();
		auto param5 = EventLogs::ParamList();
		param1.push_back(std::make_pair(L"Name", L"'Image'"));
		param2.push_back(std::make_pair(L"Name", L"'ProcessId'"));
		param3.push_back(std::make_pair(L"Name", L"'TargetFilename'"));
		param4.push_back(std::make_pair(L"Name", L"'CreationUtcTime'"));
		param5.push_back(std::make_pair(L"Name", L"'PreviousCreationUtcTime'"));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param1));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param2));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param3));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param4));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param5));

		auto results = EventLogs::QueryEvents(L"Microsoft-Windows-Sysmon/Operational", 2, queries);

		for (auto result : results)
			reaction.EventIdentified(EventLogs::EventLogItemToDetection(result));

		reaction.EndHunt();
		return results.size();
	}

	std::vector<std::shared_ptr<Event>> HuntT1099::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;
		events.push_back(std::make_shared<EventLogEvent>(L"Microsoft-Windows-Sysmon/Operational", 2));
		return events;
	}

}