#pragma once
#include "Log.h"
#include "LogLevel.h"
#include "LogSink.h"

#include "reactions/Reaction.h"
#include "hunts/hunt.h"

#include <vector>
#include <string>

#define LOG_HUNT_BEGIN(...)
#define LOG_HUNT_DETECTION(...)
#define LOG_HUNT_END(...)

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
		const HuntInfo& HuntName;

	public:

		/**
		 * Creates a log message at a given level and with a vector of sinks.
		 *
		 * @param Hunt A HuntInfo struct containing information about the hunt.
		 * @param sinks The sinks that this message will log itself to.
		 */
		HuntLogMessage(const HuntInfo& Hunt, std::vector<std::reference_wrapper<LogSink>> sinks);

		/**
		 * Creates a log message at a given level and with a sink.
		 *
		 * @param Hunt A HuntInfo struct containing information about the hunt.
		 * @param sink The sink that this message will log itself to.
		 */
		HuntLogMessage(const HuntInfo& Hunt, const LogSink& sink);

		/**
		 * Records a detection to the hunt.
		 *
		 * @param detection The detection to record. This should be an instance of 
		 *		  FILE_DETECTION, REGISTRY_DETECTION, SERIVCE_DETECTION, or PROCESS_DETECTION.
		 */
		void AddDetection(DETECTION* detection);

		/**
		 * When the LogTerminator is supplied to the stream, the stream is terminated and forwarded to
		 * the sinks for recording. After this happens, the log message is emptied and able to be used
		 * again.
		 *
		 * @param terminator An instance of the LogTerminator class used to denote the termination of a
		 *        message
		 *
		 * @return a reference to this log message.
		 */
		virtual LogMessage& operator<<(const LogTerminator& termiantor);

		using LogMessage::operator<<;
	};

	/**
	 * Adds a sink to the vector of default sinks to be used in LOG_HUNT_*.
	 * If the provided sink is equal to any sink in the vector already, this will return false
	 * and the sink will not be added.
	 *
	 * @param sink The sink to be added
	 *
	 * @return A boolean indicating whether or not the sink was added
	 */
	bool AddHuntSink(const LogSink& sink);

	/**
	 * Removes a sink from the vector of default sinks to be used in LOG_ERROR, LOG_WARNING, etc.
	 * If the provided sink is not equal to any sink in the vector already, this will return false
	 * and nothing will happen.
	 *
	 * @param sink The sink to be removed
	 *
	 * @return A boolean indicating whether or not the sink was removed
	 */
	bool RemoveHuntSink(const LogSink& sink);
}
