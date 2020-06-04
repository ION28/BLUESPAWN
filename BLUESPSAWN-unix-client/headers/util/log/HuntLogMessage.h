#pragma once
#include "Log.h"
#include "LogLevel.h"
#include "LogSink.h"

#include "reaction/Detections.h"
#include "hunt/HuntInfo.h"

#include <vector>
#include <string>
#include <memory>

// Creates a Hunt log message named _HuntLogMessage. This macro is only to be called inside
// ScanCursory, ScanNormal, or ScanIntensive.
#define LOG_HUNT_BEGIN() \
    auto _HuntLogMessage = Log::HuntLogMessage(GET_INFO(), Log::_LogHuntSinks)

// Logs a detection to the log message for the current hunt. LOG_HUNT_BEGIN should be called first.
#define LOG_HUNT_DETECTION(detection) _HuntLogMessage.AddDetection(std::static_pointer_cast<DETECTION>(detection))

// Adds a message to the log for this hunt. LOG_HUNT_BEGIN should be called first.
#define LOG_HUNT_MESSAGE(...) _HuntLogMessage << __VA_ARGS__

// Terminates the current hunt's log message. LOG_HUNT_BEGIN should be called first.
// Note that this must be called in order for the message to actually be logged.
#define LOG_HUNT_END() _HuntLogMessage << Log::endlog

namespace Log {

	// A vector containing the set of sinks to be used when LOG_HUNT is used.
	// This vector is updated by the AddHuntSink and RemoveHuntSink functions.
	extern std::vector<std::shared_ptr<LogSink>> _LogHuntSinks;

	/**
	 * This class is a specialization of the LogMessage class designed to handle detections
	 * from a hunt. When a hunt is started, it should create a new HuntLogMessage. With each
	 * detection, it should add the detection to the HuntLogMessage. When the hunt is finished,
	 * it should stream a LogTerminator to the HuntLogMessage.
	 */
	class HuntLogMessage : public LogMessage {
	protected:
		std::vector<std::shared_ptr<DETECTION>> Detections;
		HuntInfo HuntName;

	public:

		/**
		 * Creates a log message at a given level and with a vector of sinks.
		 *
		 * @param Hunt A HuntInfo struct containing information about the hunt.
		 * @param sinks The sinks that this message will log itself to.
		 */
		HuntLogMessage(const HuntInfo& Hunt, const std::vector<std::shared_ptr<LogSink>>& sinks);

		/**
		 * Creates a log message at a given level and with a sink.
		 *
		 * @param Hunt A HuntInfo struct containing information about the hunt.
		 * @param sink The sink that this message will log itself to.
		 */
		HuntLogMessage(const HuntInfo& Hunt, const std::shared_ptr<LogSink>& sink);

		/**
		 * Records a detection to the hunt.
		 *
		 * @param detection The detection to record. This should be an instance of 
		 *		  FILE_DETECTION, REGISTRY_DETECTION, SERIVCE_DETECTION, or PROCESS_DETECTION.
		 */
		void AddDetection(std::shared_ptr<DETECTION> detection);

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

		/**
		 * Copy overload for =. Copies hunt information, sinks, the message, and any detections.
		 *
		 * @param message The message to copy from.
		 *
		 * @return The new value of *this;
		 */
		HuntLogMessage operator =(const HuntLogMessage& message);
		HuntLogMessage(const HuntLogMessage& message);
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
	bool AddHuntSink(const std::shared_ptr<LogSink>& sink);

	/**
	 * Removes a sink from the vector of default sinks to be used in LOG_ERROR, LOG_WARNING, etc.
	 * If the provided sink is not equal to any sink in the vector already, this will return false
	 * and nothing will happen.
	 *
	 * @param sink The sink to be removed
	 *
	 * @return A boolean indicating whether or not the sink was removed
	 */
	bool RemoveHuntSink(const std::shared_ptr<LogSink>& sink);
}
