#include <string>
#include <iostream>

#include "reaction/SuspendProcess.h"
#include "common/wrappers.hpp"
#include "util/log/Log.h"

#include <psapi.h>

LINK_FUNCTION(NtSuspendProcess, NTDLL.DLL)

namespace Reactions{

	void SuspendProcessReaction::SuspendProcessIdentified(std::shared_ptr<PROCESS_DETECTION> detection){
		HandleWrapper process = OpenProcess(PROCESS_SUSPEND_RESUME, false, detection->PID);
		if(process){
			if(io.GetUserConfirm(detection->wsCmdline + L" appears to be infected. Suspend process?") == 1){
				Linker::NtSuspendProcess(process);
			}
		} else {
			LOG_ERROR("Unable to open potentially infected process " << detection->PID);
		}
	}

}