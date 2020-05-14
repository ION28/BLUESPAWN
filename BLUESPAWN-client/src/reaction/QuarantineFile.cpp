#include <string>
#include <iostream>

#include "reaction/QuarantineFile.h"
#include "common/wrappers.hpp"

#include "util/log/Log.h"

namespace Reactions {

	void QuarantineFileReaction::QuarantineFileIdentified(std::shared_ptr<FILE_DETECTION> detection) {
		if (io.GetUserConfirm(L"File " + detection->wsFilePath + L" appears to be malicious. Quarantine file?") == 1) {
			if (!detection->fFile.Quarantine()) {
				LOG_ERROR("Unable to quarantine file " << detection->wsFilePath << ". (Error " << GetLastError() << ")");
			}
		}
	}

	QuarantineFileReaction::QuarantineFileReaction(const IOBase& io) : io{ io } {
		vFileReactions.emplace_back(std::bind(&QuarantineFileReaction::QuarantineFileIdentified, this, std::placeholders::_1));
	}
}