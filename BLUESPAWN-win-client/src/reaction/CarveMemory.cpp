#include "reaction/CarveMemory.h"

#include <iostream>
#include <string>

#include "util/log/Log.h"
#include "util/processes/PERemover.h"

#include "user/bluespawn.h"

namespace Reactions {

    void CarveMemoryReaction::React(IN Detection& detection) {
        auto& data{ std::get<ProcessDetectionData>(detection.data) };
        if(!data.PID) {
            return;
        }

        HandleWrapper process{ OpenProcess(PROCESS_SUSPEND_RESUME, false, *data.PID) };
        if(process) {
            if(Bluespawn::io.GetUserConfirm(L"`" + (data.ProcessCommand ? *data.ProcessCommand : *data.ProcessName) +
                                            L"` (PID " + std::to_wstring(*data.PID) +
                                            L") appears to be infected. "
                                            "Carve out infected memory?") == 1) {
                if(data.ImageName) {
                    if(!PERemover{ *data.PID, *data.ImageName }.RemoveImage()) {
                        LOG_ERROR(L"Failed to carve image " << *data.ImageName << L" from process with PID "
                                                            << *data.PID);
                    } else {
                        LOG_INFO(1, L"Successfully carved image " << *data.ImageName << L" from process with PID "
                                                                  << *data.PID);
                    }
                } else {
                    if(!PERemover{ *data.PID, *data.BaseAddress, *data.MemorySize }.RemoveImage()) {
                        LOG_ERROR(L"Failed to carve memory at " << *data.BaseAddress << L" from process with PID "
                                                                << *data.PID);
                    } else {
                        LOG_INFO(1, L"Successfully carved memory at " << *data.BaseAddress << L" from process with PID "
                                                                      << *data.PID);
                    }
                }
            }
        } else {
            LOG_ERROR("Unable to open potentially infected process " << *data.PID);
        }
    }

    bool CarveMemoryReaction::Applies(IN CONST Detection& detection) {
        return !detection.DetectionStale && detection.type == DetectionType::ProcessDetection &&
               std::get<ProcessDetectionData>(detection.data).type != ProcessDetectionType::MaliciousProcess;
    }
}   // namespace Reactions
