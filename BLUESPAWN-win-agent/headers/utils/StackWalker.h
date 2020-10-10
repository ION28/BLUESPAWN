#pragma once

#include <Windows.h>

#include <vector>

#include "hooking/Address.h"
#include "utils/Common.h"

namespace BLUESPAWN::Agent::Util {

	extern CriticalSection dbghelpGuard;

	_Success_(return == true)
	bool WalkStack(_Out_ std::vector<Address>& addresses);
}