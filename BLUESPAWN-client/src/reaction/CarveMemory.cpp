#include <string>
#include <iostream>

#include "reaction/CarveMemory.h"
#include "util/log/Log.h"
#include "util/processes/PERemover.h"

namespace Reactions {

	void CarveProcessReaction::CarveProcessIdentified(std::shared_ptr<PROCESS_DETECTION> detection){
		if(io.GetUserConfirm(detection->wsCmdline + L" appears to be infected. Suspend process?") == 1){
			auto remover = PERemover{ static_cast<DWORD>(detection->PID), detection->lpAllocationBase, detection->dwAllocationSize };
			remover.RemoveImage();
		}
	}

	CarveProcessReaction::CarveProcessReaction(const IOBase& io) : io{ io }{
		vProcessReactions.emplace_back(std::bind(&CarveProcessReaction::CarveProcessIdentified, this, std::placeholders::_1));
	}
}