#pragma once
#include <Windows.h>
#include "Scope.h"
#include "Reaction.h"

class HuntRegister;

namespace Tactic {
	enum Tactic {
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
};

namespace DataSource {
	enum DataSource {
		Services = 1,
		Processes = 2,
		Drivers = 4,
		FileSystem = 8,
		Registry = 0x10,
		GPO = 0x20,
		EventLogs = 0x40,
		Network = 0x80
	};
};

namespace AffectedThing {
	enum AffectedThing {

		// Includes registry, group policy, and related configurations/settings
		Configurations = 0x1,

		// Includes services and drivers
		Processes = 0x2,

		Files = 0x4,
		Network = 0x8
	};
};

namespace Aggressiveness {
	enum Aggressiveness {
		Cursory = 0x1,
		Moderate = 0x2,
		Careful = 0x4,
		Aggressive = 0x8
	};
};

class Hunt {
protected:
	DWORD dwTacticsUsed;
	DWORD dwSourcesInvolved;
	DWORD dwStuffAffected;
	DWORD dwSupportedScans;

public:
	Hunt(HuntRegister& hr);

	bool UsesTactics(DWORD tactics);
	bool UsesSources(DWORD sources);
	bool AffectsStuff(DWORD stuff);
	bool SupportsScan(Aggressiveness::Aggressiveness scan);

	virtual int ScanCursory(Scope& scope, Reaction* reaction = nullptr);
	virtual int ScanModerate(Scope& scope, Reaction* reaction = nullptr);
	virtual int ScanCareful(Scope& scope, Reaction* reaction = nullptr);
	virtual int ScanAggressive(Scope& scope, Reaction* reaction = nullptr);
};