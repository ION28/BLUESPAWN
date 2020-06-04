#include <string>
#include <iostream>

#include "reaction/CarveMemory.h"
#include "util/log/Log.h"

namespace Reactions {

	void CarveProcessReaction::CarveProcessIdentified(std::shared_ptr<PROCESS_DETECTION> detection){
		if(io.GetUserConfirm(detection->wsImagePath + " (PID " + std::to_string(detection->PID) + ") appears to be infected. Carve out and terminate malicious memory section?") == 1){
			auto remover = PERemover{ static_cast<unsigned int>(detection->PID), detection->lpAllocationBase, detection->dwAllocationSize };
			remover.RemoveImage();
		}
	}

	CarveProcessReaction::CarveProcessReaction(const IOBase& io) : io{ io }{
		vProcessReactions.emplace_back(std::bind(&CarveProcessReaction::CarveProcessIdentified, this, std::placeholders::_1));
	}
}