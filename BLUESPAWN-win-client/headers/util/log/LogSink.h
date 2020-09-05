#pragma once

#include <string>
#include <vector>
#include <memory>
#include <optional>

#include "scan/Detections.h"
#include "hunt/HuntInfo.h"

#include "LogLevel.h"

namespace Log {
	/**
	 * LogSink provides an interface for more sinks to be added and integrate with the
	 * logging framework. 
	 *
	 * In this framework, all log messages are sent to some number of sinks, and the sinks
	 * are the endpoints of the logging. A sink may be a file to be written to, a console to
	 * be outputted to, a network connection to be transmitted to, or something else entirely.
	 * Inheriting from LogSink allows a class to interface with the logging framework and 
	 * receive messages to log.
	 */
	class LogSink {
	public:

		/**
		 * This function should be implemented to log a given message at a given level.
		 *
		 * @param level The level at which to log
		 * @param message The message to be logged
		 */
		virtual void LogMessage(const LogLevel& level, const std::wstring& message) = 0;

		/**
		 * This function should be implemented to determine whether two log sinks are equal.
		 * This function is used in the AddSink and RemoveSink methods to prevent duplicates
		 * and to determine which sink should be removed.
		 *
		 * @param sink The sink to check for equality.
		 *
		 * @return Whether or not the argument and this sink are considered equal.
		 */
		virtual bool operator==(const LogSink& sink) const = 0;
	};
}