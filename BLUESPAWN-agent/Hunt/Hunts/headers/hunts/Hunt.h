#pragma once
#include <Windows.h>

#include <string>
#include <chrono>

#include "Scope.h"
#include "reactions/Reaction.h"

class HuntRegister;

enum class Tactic {
	InitialAccess = 1,
	Execution = 2,
	Persistence = 4,
	PrivilegeEscalation = 8,
	DefenseEvasion = 0x10,
	CredentialAccess = 0x20,
	Discovery = 0x40,
	LateralMovement = 0x80,
	Collection = 0x100,
	CommandControl = 0x200,
	Exfiltration = 0x400,
	Impact = 0x800
};

enum class DataSource {
	Services = 1,
	Processes = 2,
	Drivers = 4,
	FileSystem = 8,
	Registry = 0x10,
	GPO = 0x20,
	EventLogs = 0x40,
	Network = 0x80
};

enum class Category {

	// Includes registry, group policy, and related configurations/settings
	Configurations = 0x1,

	// Includes services and drivers
	Processes = 0x2,

	Files = 0x4,
	Network = 0x8
};

enum class Aggressiveness {
	Cursory = 0x1, // Most obvious indicators (least false positives)
	Moderate = 0x2, // Examine more things
	Careful = 0x4, // Examine even more things
	Aggressive = 0x8 // Check everything imaginable (most false positives)
};

// This struct is a POD type for storing information about a hunt to be logged.
struct HuntInfo {
	std::wstring HuntName;
	Aggressiveness HuntAggressiveness;
	DWORD HuntTactics;
	DWORD HuntCategories;
	DWORD HuntDatasources;
	long HuntStartTime;
};

#define GET_INFO() \
    HuntInfo{ this->name, __func__ == std::string{"ScanCursory"}  ? Aggressiveness::Cursory  :                             \
                          __func__ == std::string{"ScanModerate"} ? Aggressiveness::Moderate :                             \
                          __func__ == std::string{"ScanCareful"}  ? Aggressiveness::Careful  : Aggressiveness::Aggressive, \
              this->dwTacticsUsed, this->dwCategoriesAffected, this->dwSourcesInvolved,                                    \
              std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() }

class Hunt {
protected:
	DWORD dwTacticsUsed;
	DWORD dwSourcesInvolved;
	DWORD dwCategoriesAffected;
	DWORD dwSupportedScans;

	std::wstring name;

public:
	Hunt(HuntRegister& hr, const std::wstring& name);

	bool UsesTactics(DWORD tactics);
	bool UsesSources(DWORD sources);
	bool AffectsCategory(DWORD category);
	bool SupportsScan(Aggressiveness scan);

	virtual int ScanCursory(const Scope& scope, Reaction* reaction = nullptr) const;
	virtual int ScanModerate(const Scope& scope, Reaction* reaction = nullptr) const;
	virtual int ScanCareful(const Scope& scope, Reaction* reaction = nullptr) const;
	virtual int ScanAggressive(const Scope& scope, Reaction* reaction = nullptr) const;
};