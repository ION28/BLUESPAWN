#pragma once
#include <Windows.h>

#include <string>
#include <chrono>

#include "Scope.h"
#include "HuntInfo.h"

#include "reaction/Reaction.h"
#include "monitor/Event.h"

class HuntRegister;

#define GET_INFO() \
    HuntInfo{ this->name, this->dwTacticsUsed, this->dwCategoriesAffected, this->dwSourcesInvolved,                                    \
              (long) std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() }

#define HUNT_INIT() \
	LOG_INFO("Hunting for " << name);          \
    LOG_HUNT_BEGIN();                          \
    std::vector<Detection> detections{};

#define REGISTRY_DETECTION(value) \
    detections.emplace_back(std::static_pointer_cast<DETECTION>(std::make_shared<REGISTRY_DETECTION>(value)));

#define FILE_DETECTION(value) \
    detections.emplace_back(std::static_pointer_cast<DETECTION>(std::make_shared<FILE_DETECTION>(value)));

#define SERVICE_DETECTION(name, path) \
    detections.emplace_back(std::static_pointer_cast<DETECTION>(std::make_shared<SERVICE_DETECTION>(name, path)));

#define EVENT_DETECTION(log) \
    detections.emplace_back(std::static_pointer_cast<DETECTION>(EventLogs::EventLogItemToDetection(log)));

#define PROCESS_DETECTION(path, cmdline, pid, module, dwModuleSize, identifiers) \
    detections.emplace_back(std::static_pointer_cast<DETECTION>(std::make_shared<PROCESS_DETECTION>(path, cmdline, pid, module, dwModuleSize, identifiers)));

#define HUNT_END()                            \
    for(const auto& detection : detections) { \
        LOG_HUNT_DETECTION(detection);        \
    }                                         \
    LOG_HUNT_END();                           \
	return detections;
    

class Hunt {
protected:
	DWORD dwTacticsUsed;
	DWORD dwSourcesInvolved;
	DWORD dwCategoriesAffected;

	std::wstring name;

public:
	Hunt(const std::wstring& name);

	std::wstring GetName();

	bool UsesTactics(DWORD tactics);
	bool UsesSources(DWORD sources);
	bool AffectsCategory(DWORD category);

	virtual std::vector<Detection> RunHunt(const Scope& scope);

	virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents();
};