#pragma once

#include <Windows.h>

#include <vector>

#include "hooking/Address.h"

namespace BLUESPAWN::Agent{

	_Success_(return == true)
	bool WalkStack(_In_ HANDLE hThread, _Out_ std::vector<Address> addresses);

	bool WalkStack(_Out_ std::vector<Address> addresses);
}