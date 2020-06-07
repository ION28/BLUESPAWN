#pragma once
#include "Reaction.h"

#include "hunt/HuntInfo.h"
#include "user/iobase.h"
#include "common/DynamicLinker.h"

#include <optional>

namespace Reactions {

	class DeleteFileReaction : public Reaction {
	private:
		const IOBase& io;

		/// Handlers for detections that log the detection
		void DeleteFileIdentified(std::shared_ptr<FILE_DETECTION> detection);

	public:
		DeleteFileReaction(const IOBase& io);
	};
}

