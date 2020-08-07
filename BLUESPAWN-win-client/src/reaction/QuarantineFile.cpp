#include "reaction/QuarantineFile.h"

#include <iostream>
#include <string>

#include "util/wrappers.hpp"

#include "util/log/Log.h"

#include "user/bluespawn.h"

namespace Reactions {
    void QuarantineFileReaction::React(IN Detection& detection) {
        auto data{ std::get<FileDetectionData>(detection.data) };
        if(Bluespawn::io.GetUserConfirm(L"File " + data.FilePath + L" appears to be malicious. Delete file?") == 1) {
            if(!data.FileHandle->Quarantine()) {
                LOG_ERROR("Unable to quarantine file " << data.FilePath << ". " << SYSTEM_ERROR);
            } else {
                detection.DetectionStale = true;
            }
        }
    }

    bool QuarantineFileReaction::Applies(IN CONST Detection& detection) {
        return !detection.DetectionStale && detection.type == DetectionType::FileDetection;
    }
}   // namespace Reactions
