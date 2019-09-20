#pragma once
#include "Reaction.h"

#include "hunts/HuntInfo.h"
#include "logging/huntlogmessage.h"

namespace Reactions {


	class LogReaction : public Reaction {
	private:
		Log::HuntLogMessage _HuntLogMessage;
		bool HuntBegun = false;

		void LogBeginHunt(const HuntInfo& info);
		void LogEndHunt();

		/// Handlers for detections that log the detection
		void LogFileIdentified(std::shared_ptr<FILE_DETECTION> detection);
		void LogRegistryKeyIdentified(std::shared_ptr<REGISTRY_DETECTION> detection);
		void LogProcessIdentified(std::shared_ptr<PROCESS_DETECTION> detection);
		void LogServiceIdentified(std::shared_ptr<SERVICE_DETECTION> detection);

	public:
		LogReaction();
	};
}

