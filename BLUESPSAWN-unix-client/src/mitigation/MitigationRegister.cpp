#include "mitigation/MitigationRegister.h"
#include "util/log/Log.h"

MitigationRegister::MitigationRegister(const IOBase& io) : io(io) {}

void MitigationRegister::RegisterMitigation(std::shared_ptr<Mitigation> mitigation) {
	vRegisteredMitigations.emplace_back(mitigation);
}

void MitigationRegister::AuditMitigations(SecurityLevel securityLevel) {
	for (int i = 0; i < vRegisteredMitigations.size(); i++) {
		if (vRegisteredMitigations[i]->MitigationApplies()) {
			if (!vRegisteredMitigations[i]->MitigationIsEnforced(securityLevel)) {
				LOG_WARNING(vRegisteredMitigations[i]->getName() + " is NOT configured.");
				io.InformUser(vRegisteredMitigations[i]->getName() + " is NOT configured.");
			}
			else {
				LOG_INFO(vRegisteredMitigations[i]->getName() + " is enabled.");
				io.InformUser(vRegisteredMitigations[i]->getName() + " is enabled.");
			}
		}
	}
	io.InformUser("Audited for presence of " + std::to_string(vRegisteredMitigations.size()) + " Mitigations.");
}

void MitigationRegister::EnforceMitigations(SecurityLevel securityLevel, bool bForceEnforce) {
	int iMitigationsIgnored = 0;
	int iEnforcedCount = 0;
	for(int i = 0; i < vRegisteredMitigations.size(); i++) {
		if (vRegisteredMitigations[i]->MitigationApplies()) {
			if (!vRegisteredMitigations[i]->MitigationIsEnforced(securityLevel)) {
				LOG_WARNING(vRegisteredMitigations[i]->getName() + " is NOT configured.");
				if (bForceEnforce) {
					LOG_WARNING("Enforcing mitigation for " + vRegisteredMitigations[i]->getName());
					io.InformUser("Enforcing mitigation for " + vRegisteredMitigations[i]->getName());
					if (vRegisteredMitigations[i]->EnforceMitigation(securityLevel)) {
						iEnforcedCount++;
					}
					else {
						LOG_WARNING("Unable to enforce mitigation for " + vRegisteredMitigations[i]->getName());
						io.InformUser("Unable to enforce mitigation for " + vRegisteredMitigations[i]->getName());
					}
				}
				else {
					io.InformUser(vRegisteredMitigations[i]->getName() + " is NOT configured.");
					unsigned int dwChoice = io.GetUserConfirm("Would you like to enforce this (y/n)");
					while (dwChoice < 0) {
						dwChoice = io.GetUserConfirm("Would you like to enforce this (y/n)");
					}
					if (dwChoice > 0) {
						LOG_INFO("Enforcing " + vRegisteredMitigations[i]->getName());
						io.InformUser("Enforcing " + vRegisteredMitigations[i]->getName());
						if (vRegisteredMitigations[i]->EnforceMitigation(securityLevel)) {
							iEnforcedCount++;
						}
						else {
							LOG_WARNING("Unable to enforce mitigation for " + vRegisteredMitigations[i]->getName());
							io.InformUser("Unable to enforce mitigation for " + vRegisteredMitigations[i]->getName());
						}
					}
					else {
						LOG_INFO("User chose not to enforce " + vRegisteredMitigations[i]->getName());
						iMitigationsIgnored++;
					}
				}
			}
		}
	}
	if (iMitigationsIgnored == 0) {
		LOG_INFO("Enforced " + std::to_string(vRegisteredMitigations.size()) + " Mitigations making " + std::to_string(iEnforcedCount) + " changes.");
		io.InformUser("Enforced " + std::to_string(vRegisteredMitigations.size()) + " Mitigations making " + std::to_string(iEnforcedCount) + " changes.");
	}
	else {
		LOG_INFO("Enforced " + std::to_string(vRegisteredMitigations.size() - iMitigationsIgnored) + " Mitigations making " + std::to_string(iEnforcedCount) +
			" changes. Chose not to enforce " + std::to_string(iMitigationsIgnored) + " Mitigations.");
		io.InformUser("Enforced " + std::to_string(vRegisteredMitigations.size() - iMitigationsIgnored) + " Mitigations making " + std::to_string(iEnforcedCount) + 
			" changes. Chose not to enforce " + std::to_string(iMitigationsIgnored) + " Mitigations.");
	}
}