#include "util/processes/ProcessUtils.h"

bool HookIsOkay(const Hook& hook){
	// Once Detours is set up, this will become significantly more complicated...
	return false;
}

std::vector<LPVOID> GetExecutableNonImageSections(DWORD pid){
	// Make use of APIs in PE Sieve...
	return {};
}
