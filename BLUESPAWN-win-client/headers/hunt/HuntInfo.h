#pragma once

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
	Normal = 0x2, // Examine more things
	Intensive = 0x3 //  Check everything imaginable (most false positives)
};

// This struct is a POD type for storing information about a hunt to be logged.
struct HuntInfo {
	std::wstring HuntName;
	DWORD HuntTactics;
	DWORD HuntCategories;
	DWORD HuntDatasources;
	long HuntStartTime;
	HuntInfo(const std::wstring& HuntName, DWORD HuntTactics, DWORD HuntCategories, DWORD HuntDatasources, long HuntStartTime);
};
