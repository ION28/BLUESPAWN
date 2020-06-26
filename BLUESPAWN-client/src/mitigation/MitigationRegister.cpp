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
				LOG_WARNING(vRegisteredMitigations[i]->getName() + L" is NOT configured.");
				io.InformUser(vRegisteredMitigations[i]->getName() + L" is NOT configured.");
			}
			else {
				LOG_INFO(1, vRegisteredMitigations[i]->getName() + L" is enabled.");
				io.InformUser(vRegisteredMitigations[i]->getName() + L" is enabled.");
			}
		}
	}
	io.InformUser(L"Audited for presence of " + std::to_wstring(vRegisteredMitigations.size()) + L" Mitigations.");
}

void MitigationRegister::EnforceMitigations(SecurityLevel securityLevel, bool bForceEnforce) {
	int iMitigationsIgnored = 0;
	int iEnforcedCount = 0;
	for(int i = 0; i < vRegisteredMitigations.size(); i++) {
		if (vRegisteredMitigations[i]->MitigationApplies()) {
			if (!vRegisteredMitigations[i]->MitigationIsEnforced(securityLevel)) {
				LOG_INFO(2, vRegisteredMitigations[i]->getName() + L" is NOT configured.");
				if (bForceEnforce) {
					LOG_INFO(1, L"Enforcing mitigation for " + vRegisteredMitigations[i]->getName());
					io.InformUser(L"Enforcing mitigation for " + vRegisteredMitigations[i]->getName());
					if (vRegisteredMitigations[i]->EnforceMitigation(securityLevel)) {
						iEnforcedCount++;
					}
					else {
						LOG_ERROR(L"Unable to enforce mitigation for " + vRegisteredMitigations[i]->getName());
						io.InformUser(L"Unable to enforce mitigation for " + vRegisteredMitigations[i]->getName());
					}
				}
				else {
					io.InformUser(vRegisteredMitigations[i]->getName() + L" is NOT configured.");
					DWORD dwChoice = io.GetUserConfirm(L"Would you like to enforce this (y/n)");
					while (dwChoice < 0) {
						dwChoice = io.GetUserConfirm(L"Would you like to enforce this (y/n)");
					}
					if (dwChoice > 0) {
						LOG_INFO(1, L"Enforcing " + vRegisteredMitigations[i]->getName());
						io.InformUser(L"Enforcing " + vRegisteredMitigations[i]->getName());
						if (vRegisteredMitigations[i]->EnforceMitigation(securityLevel)) {
							iEnforcedCount++;
						}
						else {
							LOG_ERROR(L"Unable to enforce mitigation for " + vRegisteredMitigations[i]->getName());
							io.InformUser(L"Unable to enforce mitigation for " + vRegisteredMitigations[i]->getName());
						}
					}
					else {
						LOG_INFO(2, L"User chose not to enforce " + vRegisteredMitigations[i]->getName());
						iMitigationsIgnored++;
					}
				}
			}
		}
	}
	if (iMitigationsIgnored == 0) {
		LOG_INFO(2, L"Enforced " + std::to_wstring(vRegisteredMitigations.size()) + L" Mitigations making " + std::to_wstring(iEnforcedCount) + L" changes.");
		io.InformUser(L"Enforced " + std::to_wstring(vRegisteredMitigations.size()) + L" Mitigations making " + std::to_wstring(iEnforcedCount) + L" changes.");
	}
	else {
		LOG_INFO(2, L"Enforced " + std::to_wstring(vRegisteredMitigations.size() - iMitigationsIgnored) + L" Mitigations making " + std::to_wstring(iEnforcedCount) +
			L" changes. Chose not to enforce " + std::to_wstring(iMitigationsIgnored) + L" Mitigations.");
		io.InformUser(L"Enforced " + std::to_wstring(vRegisteredMitigations.size() - iMitigationsIgnored) + L" Mitigations making " + std::to_wstring(iEnforcedCount) + 
			L" changes. Chose not to enforce " + std::to_wstring(iMitigationsIgnored) + L" Mitigations.");
	}
}