#pragma once

#include "Mitigation.h"
#include <vector>

class MitigationRegister {

public:
	void RegisterMitigation(std::shared_ptr<Mitigation> mitigation);
	void ApplyMitigations(SecurityLevel securityLevel);

private:
	std::vector<std::shared_ptr<Mitigation>> vRegisteredMitigations{};

};

