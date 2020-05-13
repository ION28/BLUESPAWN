#include <string>
#include <iostream>

#include "reaction/DeleteFile.h"
#include "common/wrappers.hpp"

#include "util/log/Log.h"

namespace Reactions {

	void DeleteFileReaction::DeleteFileIdentified(std::shared_ptr<FILE_DETECTION> detection) {
		if (io.GetUserConfirm(L"File " + detection->wsFilePath + L" appears to be malicious. Delete file?") == 1) {
			if (!detection->fFile.TakeOwnership()) {
				LOG_ERROR("Unable to take ownership of file, still attempting to delete. (Error: " << GetLastError() << ")");
			}
			if (!detection->fFile.Delete()) {
				LOG_ERROR("Unable to delete file " << detection->wsFilePath << ". (Error " << GetLastError() << ")");
			}
		}
	}

	DeleteFileReaction::DeleteFileReaction(const IOBase& io) : io{ io } {
		vFileReactions.emplace_back(std::bind(&DeleteFileReaction::DeleteFileIdentified, this, std::placeholders::_1));
	}
}