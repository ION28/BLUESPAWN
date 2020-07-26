#include "reaction/DeleteFile.h"

#include <iostream>
#include <string>

#include "util/wrappers.hpp"

#include "util/log/Log.h"

#include "user/bluespawn.h"

namespace Reactions {

    void DeleteFileReaction::React(IN Detection& detection) {
        auto data{ std::get<FileDetectionData>(detection.data) };
        if(Bluespawn::io.GetUserConfirm(L"File " + data.FilePath + L" appears to be malicious. Delete file?") == 1) {
            if(!data.FileHandle->TakeOwnership()) {
                LOG_ERROR("Unable to take ownership of file, still attempting to delete. " << SYSTEM_ERROR);
            }
            ACCESS_MASK del{ 0 };
            Permissions::AccessAddDelete(del);
            std::optional<Permissions::Owner> BluespawnOwner = Permissions::GetProcessOwner();
            if(BluespawnOwner == std::nullopt) {
                LOG_ERROR("Unable to get process owner, still attempting to delete. " << SYSTEM_ERROR);
            } else {
                if(!data.FileHandle->GrantPermissions(*BluespawnOwner, del)) {
                    LOG_ERROR("Unable to grant delete permission, still attempting to delete. (Error: "
                              << GetLastError() << ")");
                }
            }
            if(!data.FileHandle->Delete()) {
                LOG_ERROR("Unable to delete file " << data.FilePath << ". " << SYSTEM_ERROR);
            } else{
                detection.DetectionStale = true;
            }
        }
    }

    bool DeleteFileReaction::Applies(IN CONST Detection& detection){
        return !detection.DetectionStale && detection.type == DetectionType::FileDetection;
    }
}   // namespace Reactions
