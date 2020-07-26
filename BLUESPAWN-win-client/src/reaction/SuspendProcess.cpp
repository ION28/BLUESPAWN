#include <string>
#include <iostream>

#include "reaction/SuspendProcess.h"
#include "util/wrappers.hpp"
#include "util/log/Log.h"
#include "user/bluespawn.h"

#include <psapi.h>

LINK_FUNCTION(NtSuspendProcess, NTDLL.DLL)

namespace Reactions{

	void SuspendProcessReaction::React(IN Detection& detection){
		auto& data{ std::get<ProcessDetectionData>(detection.data) };
		if(data.PID){
			HandleWrapper process{ OpenProcess(PROCESS_SUSPEND_RESUME, false, *data.PID) };
			if(process){
				if(Bluespawn::io.GetUserConfirm(L"`" + (data.ProcessCommand ? *data.ProcessCommand : *data.ProcessName) +
												L"` (PID " + std::to_wstring(*data.PID) + L") appears to be infected. "
												"Suspend process?") == 1){
					Linker::NtSuspendProcess(process);
				}
			} else{
				LOG_ERROR("Unable to open potentially infected process " << *data.PID);
			}
		}
	}

	bool SuspendProcessReaction::Applies(IN CONST Detection& detection){
		return !detection.DetectionStale && detection.type == DetectionType::ProcessDetection;
	}
}