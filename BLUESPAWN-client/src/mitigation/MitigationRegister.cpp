#include "mitigation/MitigationRegister.h"
#include <iostream>
#include <string>

void MitigationRegister::RegisterMitigation(Mitigation* mitigation) {
	vRegisteredMitigations.emplace_back(mitigation);
}

void MitigationRegister::SetSecurityLevel(SecurityLevel securityLevel) {
	for(int i=0; i < vRegisteredMitigations.size(); i++) {
		
		/*
		// For each mitigation, if not enforced at the current security level ask if it should be
		if(!vRegisteredMitigations[i]->isEnforced(securityLevel)) {
			std::string answer = "";
			while(answer != "y" && answer != "n") {
				std::cout << "Enforce " << vRegisteredMitigations[i]->getName() << ": " << vRegisteredMitigations[i]->getDescription() << "? [y][n]" << std::endl;
				std::getline(std::cin, answer);
			}
			
			if (answer == "y") {
				vRegisteredMitigations[i]->enforce(securityLevel);
			}
		}
		*/
	}
}

void MitigationRegister::RunMitigationsAnalysis(const Reaction& reaction) {
	for (auto name : vRegisteredMitigations) {
		name->isEnforced(SecurityLevel::High, reaction);
	}
}
