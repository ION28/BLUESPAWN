#pragma once

#include "Mitigation.h"
#include <vector>

class MitigationRegister {

	public:
		void RegisterMitigation(Mitigation* mitigation);
		void SetSecurityLevel(SecurityLevel securityLevel);

	private:
		std::vector<Mitigation*> vRegisteredMitigations{};

};

