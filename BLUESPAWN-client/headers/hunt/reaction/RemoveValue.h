#pragma once
#include "Reaction.h"

#include "hunt/HuntInfo.h"
#include "user/iobase.h"
#include "common/DynamicLinker.h"

#include <optional>

namespace Reactions{

	class RemoveValueReaction : public Reaction {
	private:
		const IOBase& io;

		/// Handlers for detections that log the detection
		void RemoveRegistryIdentified(std::shared_ptr<REGISTRY_DETECTION> detection);

	public:
		RemoveValueReaction(const IOBase& io);
	};
}

