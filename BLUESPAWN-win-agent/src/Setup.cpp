#include "Setup.h"
#include "utils/Debug.h"

bool BLUESPAWN::Agent::PerformAttachActions(){
	LOG_DEBUG_MESSAGE(LOG_INFO, "DLL loaded");

	return true;
}

bool BLUESPAWN::Agent::PerformDetachActions(){
	LOG_DEBUG_MESSAGE(LOG_INFO, "DLL unloaded");

	return true;
}