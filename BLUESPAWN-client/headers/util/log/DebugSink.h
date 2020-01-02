#pragma once
#include "LogSink.h"

namespace Log {

	/**
	 * DebugSink provides a sink for the logger that directs output to the debug console.
	 *
	 * Each log message is prepended with the severity of the log, as defined in
	 * MessagePrepends.
	 */
	class DebugSink : public LogSink {
	private:
		std::string MessagePrepends[4] = { "[ERROR]", "[WARNING]", "[INFO]", "[OTHER]" };

	public:

		/**
		 * Outputs a message to the debug console if its logging level is enabled. The log message
		 * is prepended with its severity level.
		 *
		 * @param level The level at which the message is being logged
		 * @param message The message to log
		 */
		virtual void LogMessage(const LogLevel& level, const std::string& message, const HuntInfo& info = {}, 
			const std::vector<std::shared_ptr<DETECTION>>& detections = {});

		/**
		 * Compares this DebugSink to another LogSink. Currently, as only one debug console is supported,
		 * any other DebugSink is considered to be equal. This is subject to change in the event that
		 * support for more consoles is added.
		 *
		 * @param sink The LogSink to compare
		 *
		 * @return Whether or not the argument and this sink are considered equal.
		 */
		virtual bool operator==(const LogSink& sink) const;
	};
}