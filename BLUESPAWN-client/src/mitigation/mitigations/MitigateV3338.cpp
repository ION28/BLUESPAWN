#include "mitigation/mitigations/MitigateV3338.h"
#include "hunt/RegistryHunt.hpp"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

using namespace Registry;

namespace Mitigations {

	MitigateV3338::MitigateV3338(MitigationRegister& record) : Mitigation(record, "V-3338 - Unauthorized named pipes are accessible with anonymous credentials.") {
		name = "V-3338 - Unauthorized named pipes are accessible with anonymous credentials.";
		description = "This is a High finding because of the potential for gaining unauthorized system access. Pipes are internal system communications processes. They are identified internally by ID numbers that vary between systems. To make access to these processes easier, these pipes are given names that do not vary between systems. This setting controls which of these pipes anonymous users may access.";
	}

	bool MitigateV3338::isEnforced(SecurityLevel level, Reaction reaction) {
		LOG_INFO("Checking for presence of V-3338 - Unauthorized named pipes are accessible with anonymous credentials");
		//reaction.("");

		int identified = 0;

		//TODO: Allow netlogon, samr, lsarpc if computer is a domain controller
		identified += CheckKey({ HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\LanManServer\\Parameters", L"NullSessionPipes" }, L"", reaction);

		//reaction.EndHunt();
		return identified;
	}

	bool MitigateV3338::enforce(SecurityLevel level, Reaction reaction) {
		return false;
	}
}