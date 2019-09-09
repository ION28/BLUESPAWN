#pragma once
#include "Reaction.h"
#include "logging/log.h"

namespace Reactions {

	/// Handlers for detections that log the detection
	void FileIdentified(FILE_DETECTION* detection);
	void RegistryKeyIdentified(REGISTRY_DETECTION* detection);
	void ProcessIdentified(PROCESS_DETECTION* detection);
	void ServiceIdentified(SERVICE_DETECTION* detection);

	class LogReaction : public Reaction {
	public:
		LogReaction();
	};
}

