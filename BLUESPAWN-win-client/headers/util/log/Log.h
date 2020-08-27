#pragma once

#include <Windows.h>
#include <string>
#include <sstream>
#include <functional>
#include <vector>

#include "LogLevel.h"
#include "Loggable.h"
#include "LogSink.h"
#include "util/Utils.h"

// A generic macro to log a message with a given set of sinks at a given level
#define LOG(LEVEL, ...) \
    Log::LogMessage(LEVEL) << __VA_ARGS__

// A macro to log an error in the set of sinks specified by AddSink and RemoveSink
#define LOG_ERROR(...) \
   LOG(Log::LogLevel::LogError, __VA_ARGS__ << Log::endlog)

// A macro to log an LSTATUS and/or HRESULT error
#define LOG_SYSTEM_ERROR(ERROR_ID) \
   LOG_ERROR("System Error Code 0x" << std::uppercase << std::hex << ERROR_ID << ": " << Log::FormatErrorMessage(ERROR_ID));

// A macro that evaluates to a string describing the code in GetLastError()
#define SYSTEM_ERROR \
	"System Error Code 0x" << std::uppercase << std::hex << GetLastError() << ": " << Log::FormatErrorMessage(GetLastError())

// A macro to log a warning in the set of sinks specified by AddSink and RemoveSink
#define LOG_WARNING(...) \
   LOG(Log::LogLevel::LogWarn, __VA_ARGS__ << Log::endlog)

// A macro to log information in the set of sinks specified by AddSink and RemoveSink
#define LOG_INFO(VERBOSITY, ...) \
   LOG(Log::LogLevel::LogInfo##VERBOSITY, __VA_ARGS__ << Log::endlog)

// A macro to log verbose information in the set of sinks specified by AddSink and RemoveSink
// at a specified verbosity. Under current configurations, this should be between 1 and 3 inclusive.
#define LOG_VERBOSE(VERBOSITY, ...) \
   LOG(Log::LogLevel::LogVerbose##VERBOSITY, __VA_ARGS__ << Log::endlog)

namespace Log {

	// A vector containing the set of sinks to be used when LOG_ERROR, LOG_WARNING, etc are used.
	// This vector is updated by the AddSink and RemoveSink functions.
	extern std::vector<std::shared_ptr<LogSink>> _LogSinks;

	// A dummy class to indicate the termination of a log message.
	class LogTerminator {};

	// Indicates the end of a log message
	extern LogTerminator endlog;

	/**
	 * A class to handle log messages built around the style of a stream. The above macros are the
	 * preferred method of interracting with this class.
	 */
	class LogMessage {
	protected:
		// The internal stream used to keep track of the log message
		std::wstringstream stream{};
		
		// The level at which the log message is being logged.
		LogLevel level;

		/**
		 * An internal constructor used create a log message based off of an already existing
		 * stream.
		 *
		 * @param level The log level at which this message is logged.
		 * @param message The pre-existing contents of the message
		 */
		LogMessage(
			IN CONST LogLevel& level,
			IN CONST std::wstringstream& message
		);

		/**
		 * StringStream does most of the work needed to handle a stream of values being logged
		 * to this message. This function serves as a wrapper around adding an object to the internal
		 * stream.
		 *
		 * @param LogItem The item to add to the log message.
		 *
		 * @return a reference to this log message.
		 */
		template<class T>
		LogMessage& InnerLog(
			IN CONST T LogItem, 
			IN CONST std::false_type&
		){
			stream << LogItem;
			return *this;
		}

		/**
		 * At some point, it may become beneficial to log the current state of a component.
		 * This is meant to serve as a handler for components implementing the Loggable
		 * interface.
		 *
		 * @param loggable The component to log
		 *
		 * @return a reference to this log message.
		 */
		LogMessage& InnerLog(
			IN CONST Loggable& loggable, 
			IN CONST std::true_type&
		);

	public:

		/**
		 * Creates a log message at a given level and with a sink
		 *
		 * @param level The log level at which this message is logged.
		 */
		LogMessage(
			IN CONST LogLevel& level
		);

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
		virtual LogMessage& operator<<(
			IN CONST LogTerminator& termiantor
		);

		/**
		 * Tag dispatcher for the InnerLog functions. Used to add elements to this log message
		 *
		 * @param LogItem Item to add to this log message
		 *
		 * @return a reference to this log message
		 */
		template<class T>
		LogMessage& operator<<(
			IN CONST T& LogItem
		){
			return InnerLog(LogItem, std::is_base_of<Loggable, T>{});
		}
	};

	/**
	 * Adds a given LogSink to the specified levels as a sink for all log messages of that level.
	 * If the provided sink is equal to any sink in the vector already, this will return false,
	 * and the sink will not be added.
	 *
	 * @param sink The sink to be added
	 * @param levels A vector of the log levels that will be logged to the sink
	 */
	void AddSink(
		IN CONST std::shared_ptr<LogSink>& sink,
		IN CONST std::vector<std::reference_wrapper<LogLevel>>& levels
	);

	/**
	* Gets a System Error Message's Description given the error code
	*
	* @param DWORD returned from GetLastError()
	*
	* @return A std::wstring containing the System Error Message Description
	*/
	std::wstring FormatErrorMessage(DWORD dwNum);
}
