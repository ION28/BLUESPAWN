#include "mitigation/MitigationRegister.h"
#include <iostream>
#include <string>

void MitigationRegister::RegisterMitigation(std::shared_ptr<Mitigation> mitigation) {
	if(mitigation->MitigationApplies()){
		vRegisteredMitigations.emplace_back(mitigation);
	}
}

void MitigationRegister::ApplyMitigations(SecurityLevel securityLevel) {
	for(int i = 0; i < vRegisteredMitigations.size(); i++) {
		if(!vRegisteredMitigations[i]->MitigationIsEnforced(securityLevel)) {
			vRegisteredMitigations[i]->EnforceMitigation(securityLevel);
		}
	}
}