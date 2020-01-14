#pragma once

#include "Mitigation.h"
#include <vector>

class MitigationRegister {

public:
	void RegisterMitigation(Mitigation* mitigation);
	void ApplyMitigations(SecurityLevel securityLevel);

private:
	std::vector<Mitigation*> vRegisteredMitigations{};

};

