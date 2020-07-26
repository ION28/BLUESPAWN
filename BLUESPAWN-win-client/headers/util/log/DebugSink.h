#pragma once

#include "LogSink.h"
#include "DetectionSink.h"

#include "util/wrappers.hpp"

namespace Log {

	/**
	 * DebugSink provides a sink for the logger that directs output to the debug console.
	 *
	 * Each log message is prepended with the severity of the log, as defined in MessagePrepends.
	 */
	class DebugSink : public LogSink, public DetectionSink {
	private:

		/// A list of different prepends to be used at each log level
		static inline std::wstring MessagePrepends[4] = { L"[ERROR]", L"[WARNING]", L"[INFO]", L"[VERBOSE]" };

		/// A critical section ensuring associated messages occur consecutively
		CriticalSection hGuard;

	public:

		/**
		 * Outputs a message to the debug console if its logging level is enabled. The log message is prepended with 
		 * its severity level.
		 *
		 * @param level The level at which the message is being logged
		 * @param message The message to log
		 */
		virtual void LogMessage(
			IN CONST LogLevel& level,
			IN CONST std::wstring& message
		) override;

		/**
		 * Compares this Debug to another LogSink. Currently, as only one debug console is supported, any other
		 * DebugSink is considered to be equal. This is subject to change in the event that support for more debug
		 * consoles is added.
		 *
		 * @param sink The LogSink to compare
		 *
		 * @return Whether or not the argument and this sink are considered equal.
		 */
		virtual bool operator==(
			IN CONST LogSink& sink
		) const;

		/**
		 * Records a detection to the debug console.
		 *
		 * @param detection The detection to record
		 * @param type The type of record this is, either PreScan or PostScan
		 */
		virtual void RecordDetection(
			IN CONST std::shared_ptr<Detection>& detection,
			IN RecordType type
		);

		/**
		 * Records an association between two detections to the console
		 *
		 * @param first The first detection in the assocation. This detection's ID will be lower than the second's.
		 * @param second The second detection in the association.
		 * @param strength The strength of the connection
		 */
		virtual void RecordAssociation(
			IN CONST std::shared_ptr<Detection>& first,
			IN CONST std::shared_ptr<Detection>& second,
			IN CONST Association& strength
		);

		/**
		 * Updates the raw and combined certainty values associated with a detection
		 *
		 * @param detection The detection to update
		 */
		virtual void UpdateCertainty(
			IN CONST std::shared_ptr<Detection>& detection
		);
	};
}