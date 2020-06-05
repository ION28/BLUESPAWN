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

#define HUNT_INIT()                      \
	LOG_INFO(1, "Hunting for " << name); \
    std::vector<std::reference_wrapper<Detection>> detections{};

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

#define HUNT_END()                             \
    LOG_INFO(2, "Finished hunt for " << name); \
	return detections;
    

class Hunt {
protected:
    
    /// The tactics used by the hunt, computed as a bitwise OR of entries in the enum Tactic
	DWORD dwTacticsUsed;

    /// The data sources used by the hunt, computed as a bitwise OR of entries in the enum DataSource
	DWORD dwSourcesInvolved;

    /// The categories affected by the hunt, computed as a bitwise OR of entries in the enum Category
	DWORD dwCategoriesAffected;

    /// The name of the hunt
	std::wstring name;

public:
	
    /**
     * Instantiates a new hunt by the given name. Note that names should be unique and include
     * the technique number as well as the name (Such as T1004 - Winlogon Helper).
     *
     * @param name The name of the hunt
     */
    Hunt(
        IN CONST std::wstring& name
    );

    /**
     * Retrieves the name of the hunt
     *
     * @return The name of the hunt
     */
	std::wstring GetName();

    /**
     * Indicate whether the hunt uses all specified tactics from the Tactic enum.
     *
     * @param tactics The tactics to check, computed as a bitwise OR of the Tactic enum.
     *
     * @return True if the hunt uses all specified tactics; false otherwise.
     */
	bool UsesTactics(
        IN DWORD tactics
    );

    /**
     * Indicate whether the hunt uses all specified sources from the Source enum.
     *
     * @param source The source to check, computed as a bitwise OR of the Source enum.
     *
     * @return True if the hunt uses all specified sources; false otherwise.
     */
	bool UsesSources(
        IN DWORD sources
    );

    /**
     * Indicate whether the hunt uses all specified categories from the Category enum.
     *
     * @param categories The categories to check, computed as a bitwise OR of the Category enum.
     *
     * @return True if the hunt uses affects specified categories; false otherwise.
     */
	bool AffectsCategory(
        IN DWORD categories
    );

	virtual std::vector<std::reference_wrapper<Detection>> RunHunt(
        IN CONST Scope& scope
    );

	virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents();
};