#pragma once
#include <Windows.h>

#include <string>
#include <chrono>

#include "Scope.h"
#include "HuntInfo.h"

#include "monitor/Event.h"

class HuntRegister;

#define GET_INFO() \
    HuntInfo{ this->name, this->dwTacticsUsed, this->dwCategoriesAffected, this->dwSourcesInvolved,                                    \
              (long) std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() }

#define HUNT_INIT()                                              \
    std::vector<std::shared_ptr<Detection>> detections{}; \
    LOG_INFO(1, "Beginning hunt for " << name);

#define HUNT_END()                             \
    LOG_INFO(2, "Finished hunt for " << name); \
	return detections;

#define CREATE_DETECTION(certainty, ...)              \
    detections.emplace_back(                          \
        Bluespawn::detections.AddDetection(Detection{ \
            __VA_ARGS__,                              \
            DetectionContext{ GetName() }             \
        }, certainty)                                 \
    );

#define CREATE_DETECTION_WITH_CONTEXT(certainty, ...) \
    detections.emplace_back(                          \
        Bluespawn::detections.AddDetection(Detection{ \
            __VA_ARGS__,                              \
        }, certainty)                                 \
    );

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

    /**
     * Runs the hunt, returning references to the detections found.
     *
     * @param scope The scope of the hunt
     *
     * @return A vector of references to the detections identified.
     */
	virtual std::vector<std::shared_ptr<Detection>> RunHunt(
        IN CONST Scope& scope
    );

    /**
     * Retrieves a vector of events to be signalled when the hunt should be rerun. This should only
     * be called once, as the events will be duplicated if called multiple times.
     *
     * @return a vector of event pointers
     */
	virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents();
};
