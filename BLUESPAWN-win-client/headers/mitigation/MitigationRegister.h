#pragma once

#include "Mitigation.h"
#include "user/CLI.h"
#include <vector>

class MitigationRegister {
	
public:
	MitigationRegister(const IOBase& oIo);

	bool ParseMitigationsJSON(const std::wstring& path);
	bool ParseMitigationsJSON(const AllocationWrapper& data);

private:
	std::vector<Mitigation> registeredMitigations{};
};

