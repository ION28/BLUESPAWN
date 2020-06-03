#include <string>
#include <iostream>

#include "reaction/DeleteFile.h"
#include "common/wrappers.hpp"

#include "util/log/Log.h"

namespace Reactions {

	void DeleteFileReaction::DeleteFileIdentified(std::shared_ptr<FILE_DETECTION> detection) {
		if (io.GetUserConfirm("File " + detection->wsFilePath + " appears to be malicious. Delete file?") == 1) {
			if (!detection->fFile.TakeOwnership()) {
				LOG_ERROR("Unable to take ownership of file, still attempting to delete. (Error: " << errno << ")");
			}
			
			std::optional<Permissions::Owner> BluespawnOwner = Permissions::GetProcessOwner();
			if(BluespawnOwner == std::nullopt){
				LOG_ERROR("Unable to get process owner, still attempting to delete. (eError: " << errno << ")");
			}else{
				std::optional<FileSystem::Folder> folder = detection->fFile.GetDirectory();
				if(!detection->fFile.CanDelete(*BluespawnOwner)){
					LOG_ERROR("We do not have permission to delete this file.  Attempting to grant it.");
					if(!folder.value().GrantPermissions(S_IXUSR | S_IWUSR)){
						LOG_ERROR("Unable to grant delete perms to file");
					}
				}
			}

			if(detection->fFile.Delete()){
				LOG_VERBOSE(2, "Deleted file");
			}else{
				LOG_ERROR("Error deleting file " << errno << ".");
			}
		}
	}

	DeleteFileReaction::DeleteFileReaction(const IOBase& io) : io{ io } {
		vFileReactions.emplace_back(std::bind(&DeleteFileReaction::DeleteFileIdentified, this, std::placeholders::_1));
	}
}