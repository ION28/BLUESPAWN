#include "Setup.h"
#include "utils/Debug.h"
#include "hooking/HookRegister.h"

#include "detours/detours.h"

bool BLUESPAWN::Agent::PerformAttachActions(){
	LOG_DEBUG_MESSAGE(LOG_INFO, "DLL loaded");

	DetourRestoreAfterWith();
	HookRegister::GetInstance().Initialize();

	return true;
}

bool BLUESPAWN::Agent::PerformDetachActions(){
	LOG_DEBUG_MESSAGE(LOG_INFO, "DLL unloaded");

	return true;
}