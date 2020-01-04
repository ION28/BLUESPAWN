#pragma once
#include "Log.h"
#include "LogLevel.h"
#include "LogSink.h"

#include "util/reaction/detections.h"

#include <vector>
#include <string>
#include <memory>

// Creates a Mitigation log message named _MitigationLogMessage.
#define LOG_MITIGATION_ANALYSIS_BEGIN() \
    auto _MitigationLogMessage = Log::MitigationLogMessage(GET_INFO(), Log::_LogMitigationSinks)

// Logs a detection to the log message for the current mitigation analysis. LOG_MITIGATION_ANALYSIS_BEGIN should be called first.
#define LOG_MITIGATION_ANALYSIS_DETECTION(detection) _MitigationLogMessage.AddDetection(std::static_pointer_cast<DETECTION>(detection))

// Adds a message to the log for this mitigation. LOG_MITIGATION_ANALYSIS_BEGIN should be called first.
#define LOG_MITIGATION_ANALYSIS_MESSAGE(...) _MitigationLogMessage << __VA_ARGS__

// Terminates the current mitigation analsys' log message. LOG_MITIGATION_ANALYSIS_BEGIN should be called first.
// Note that this must be called in order for the message to actually be logged.
#define LOG_MITIGATION_ANALYSIS_END() _MitigationLogMessage << Log::endlog

namespace Log {

	// A vector containing the set of sinks to be used when LOG_HUNT is used.
	// This vector is updated by the AddHuntSink and RemoveHuntSink functions.
	extern std::vector<std::reference_wrapper<LogSink>> _LogMitigationSinks;

	/**
	 * This class is a specialization of the LogMessage class designed to handle detections
	 * from a hunt. When a hunt is started, it should create a new HuntLogMessage. With each
	 * detection, it should add the detection to the HuntLogMessage. When the hunt is finished,
	 * it should stream a LogTerminator to the HuntLogMessage.
	 */
	class MitigationLogMessage : public LogMessage {
	protected:
		std::vector<std::shared_ptr<DETECTION>> Detections;

	public:

		/**
		 * Creates a log message at a given level and with a vector of sinks.
		 *
		 * @param sinks The sinks that this message will log itself to.
		 */
		MitigationLogMessage(const std::vector<std::reference_wrapper<LogSink>>& sinks);

		/**
		 * Creates a log message at a given level and with a sink.
		 *
		 * @param sink The sink that this message will log itself to.
		 */
		MitigationLogMessage(const LogSink& sink);

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
		MitigationLogMessage operator =(const MitigationLogMessage& message);
		MitigationLogMessage(const MitigationLogMessage& message);
	};

	/**
	 * Adds a sink to the vector of default sinks to be used in LOG_MITIGATION_ANALYSIS_*.
	 * If the provided sink is equal to any sink in the vector already, this will return false
	 * and the sink will not be added.
	 *
	 * @param sink The sink to be added
	 *
	 * @return A boolean indicating whether or not the sink was added
	 */
	bool AddMitigationSink(const LogSink& sink);

	/**
	 * Removes a sink from the vector of default sinks to be used in LOG_ERROR, LOG_WARNING, etc.
	 * If the provided sink is not equal to any sink in the vector already, this will return false
	 * and nothing will happen.
	 *
	 * @param sink The sink to be removed
	 *
	 * @return A boolean indicating whether or not the sink was removed
	 */
	bool RemoveMitigationSink(const LogSink& sink);
}
