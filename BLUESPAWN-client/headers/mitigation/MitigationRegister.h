#pragma once

#include "Mitigation.h"
#include <vector>

class MitigationRegister {

	public:
		void RegisterMitigation(Mitigation* mitigation);
		void SetSecurityLevel(SecurityLevel securityLevel);
		void RunMitigationsAnalysis(const Reaction& reaction);
		void RunMitigationAnalysis(const Reaction& reaction);

	private:
		std::vector<Mitigation*> vRegisteredMitigations{};

};

