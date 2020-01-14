#include "mitigation/MitigationRegister.h"

void MitigationRegister::RegisterMitigation(Mitigation* mitigation) {
	vRegisteredMitigations.emplace_back(mitigation);
}

void MitigationRegister::ApplyMitigations(SecurityLevel securityLevel) {
	for(int i = 0; i < vRegisteredMitigations.size(); i++) {
		if (vRegisteredMitigations[i]->MitigationApplies()) {
			if (!vRegisteredMitigations[i]->MitigationIsEnforced(securityLevel)) {
				vRegisteredMitigations[i]->EnforceMitigation(securityLevel);
			}
		}
	}
}