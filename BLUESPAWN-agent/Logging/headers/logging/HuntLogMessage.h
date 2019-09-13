#pragma once
#include "Log.h"
#include "LogLevel.h"
#include "LogSink.h"

#include "reactions/Reaction.h"

#include <vector>
#include <string>

namespace Log {

	// A vector containing the set of sinks to be used when LOG_HUNT is used.
	// This vector is updated by the AddHuntSink and RemoveHuntSink functions.
	extern std::vector<std::reference_wrapper<LogSink>> _LogHuntSinks;

	/**
	 * This class is a specialization of the LogMessage class designed to handle detections
	 * from a hunt. When a hunt is started, it should create a new HuntLogMessage. With each
	 * detection, it should add the detection to the HuntLogMessage. When the hunt is finished,
	 * it should stream a LogTerminator to the HuntLogMessage.
	 */
	class HuntLogMessage : public LogMessage {
	protected:
		std::vector<DETECTION*> Detections;
		std::wstring HuntName;

	public:

		/**
		 * Creates a log message at a given level and with a vector of sinks
		 *
		 * @param sinks The sinks that this message will log itself to.
		 * @param level The log level at which this message is logged.
		 */
		HuntLogMessage(std::wstring Hunt, std::vector<std::reference_wrapper<LogSink>> sinks, LogLevel level);

		/**
		 * Creates a log message at a given level and with a sink
		 *
		 * @param sink The sink that this message will log itself to.
		 * @param level The log level at which this message is logged.
		 */
		HuntLogMessage(std::wstring Hunt, LogSink& sink, LogLevel level);

		/**
		 * Records a detection to the hunt
		 *
		 * @param detection The detection to record. This should be an instance of 
		 *		  FILE_DETECTION, REGISTRY_DETECTION, SERIVCE_DETECTION, or PROCESS_DETECTION.
		 */
		void AddDetection(DETECTION* detection);
	};
}
