#pragma once

#include "Mitigation.h"
#include "user/CLI.h"
#include <vector>

class MitigationRegister {

public:
	MitigationRegister(IOBase& oIo);
	void RegisterMitigation(std::shared_ptr<Mitigation> mitigation);
	void AuditMitigations(SecurityLevel securityLevel);
	void EnforceMitigations(SecurityLevel securityLevel, bool bForceEnforce);

private:
	std::vector<std::shared_ptr<Mitigation>> vRegisteredMitigations{};
	IOBase& io;
};

