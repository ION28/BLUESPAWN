#include "mitigation/mitigations/MitigateV72753.h"
#include "hunt/RegistryHunt.hpp"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

using namespace Registry;

namespace Mitigations {

	MitigateV72753::MitigateV72753(MitigationRegister& record) : Mitigation(record, "V-72753 - WDigest Authentication must be disabled.") {
		name = "V-72753 - WDigest Authentication must be disabled.";
		description = "When the WDigest Authentication protocol is enabled, plain text passwords are stored in the Local Security Authority Subsystem Service (LSASS) exposing them to theft. This setting will prevent WDigest from storing credentials in memory.";
	}

	bool MitigateV72753::isEnforced(SecurityLevel level, Reaction reaction) {
		LOG_INFO("Checking for presence of V-72753 - WDigest Authentication must be disabled");
		//reaction.("");

		int identified = 0;

		//TODO: Allow netlogon, samr, lsarpc if computer is a domain controller
		identified += CheckKey({ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest", L"UseLogonCredential" }, 0, reaction);

		//reaction.EndHunt();
		return identified;
	}

	bool MitigateV72753::enforce(SecurityLevel level, Reaction reaction) {
		return false;
	}
}