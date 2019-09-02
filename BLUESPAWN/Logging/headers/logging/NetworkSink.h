#pragma once

#include <map>

#include "LogSink.h"
#include "LogLevel.h"

namespace Log {

	/**
	 * NetworkSink provides a sink for the logger that directs output to the console.
	 *
	 * Each log message is prepended with the severity of the log, as defined in
	 * MessagePrepends.
	 */
	class NetworkSink : public LogSink {
	private:
		std::string MessagePrepends[4] = { "[ERROR]", "[WARNING]", "[INFO]", "[OTHER]" };

	public:

		/**
		 * Outputs a message to the console if its logging level is enabled. The log message
		 * is prepended with its severity level.
		 *
		 * @param level The level at which the message is being logged
		 * @param message The message to log
		 */
		virtual void LogMessage(LogLevel& level, std::string& message);

		/**
		 * Compares this NetworkSink to another LogSink. Currently, as only one console is supported,
		 * any other NetworkSink is considered to be equal. This is subject to change in the event that
		 * support for more consoles is added.
		 *
		 * @param sink The LogSink to compare
		 *
		 * @return Whether or not the argument and this sink are considered equal.
		 */
		virtual bool operator==(LogSink& sink);
	};
}
