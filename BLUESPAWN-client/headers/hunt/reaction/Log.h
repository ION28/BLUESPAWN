#pragma once
#include "Reaction.h"

#include "hunt/HuntInfo.h"
#include "util/log/huntlogmessage.h"

#include <optional>

namespace Reactions {

	class LogReaction : public Reaction {
	private:
		std::optional<Log::HuntLogMessage> _HuntLogMessage;
		bool HuntBegun = false;

		void LogBeginHunt(const HuntInfo& info);
		void LogEndHunt();

		/// Handlers for detections that log the detection
		void LogFileIdentified(std::shared_ptr<FILE_DETECTION> detection);
		void LogRegistryKeyIdentified(std::shared_ptr<REGISTRY_DETECTION> detection);
		void LogProcessIdentified(std::shared_ptr<PROCESS_DETECTION> detection);
		void LogServiceIdentified(std::shared_ptr<SERVICE_DETECTION> detection);
		void LogEventIdentified(std::shared_ptr<EVENT_DETECTION> detection);

	public:
		LogReaction();
	};
}

