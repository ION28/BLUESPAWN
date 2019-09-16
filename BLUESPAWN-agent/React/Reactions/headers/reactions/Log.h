#pragma once
#include "Reaction.h"

#include "hunts/HuntInfo.h"
#include "logging/huntlogmessage.h"

namespace Reactions {


	class LogReaction : public Reaction {
	private:
		Log::HuntLogMessage _HuntLogMessage;
		bool HuntBegun = false;

		void BeginHunt(const HuntInfo& info);
		void EndHunt();

		/// Handlers for detections that log the detection
		void FileIdentified(FILE_DETECTION* detection);
		void RegistryKeyIdentified(REGISTRY_DETECTION* detection);
		void ProcessIdentified(PROCESS_DETECTION* detection);
		void ServiceIdentified(SERVICE_DETECTION* detection);

	public:
		LogReaction();
	};
}

