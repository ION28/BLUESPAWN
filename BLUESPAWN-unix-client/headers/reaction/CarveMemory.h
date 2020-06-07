#pragma once
#include "Reaction.h"

#include "hunt/HuntInfo.h"
#include "user/iobase.h"

namespace Reactions{

	class CarveProcessReaction : public Reaction {
	private:
		const IOBase& io;

		/// Handlers for detections that log the detection
		void CarveProcessIdentified(std::shared_ptr<PROCESS_DETECTION> detection);

	public:
		CarveProcessReaction(const IOBase& io);
	};
}

