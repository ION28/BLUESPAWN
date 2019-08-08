#pragma once

#include <Windows.h>
#include <string>
#include <sstream>
#include <functional>
#include <vector>

#include "LogLevel.h"
#include "Loggable.h"
#include "LogSink.h"

// A generic macro to log a message with a given set of sinks at a given level
#define LOG(SINK, LEVEL, ...) \
    Log::LogMessage(SINK, LEVEL) << __VA_ARGS__

// A macro to log an error in the set of sinks specified by AddSink and RemoveSink
#define LOG_ERROR(...) \
   LOG(Log::_LogCurrentSinks, Log::LogLevel::LogError, __VA_ARGS__ << Log::endlog)

// A macro to log a warning in the set of sinks specified by AddSink and RemoveSink
#define LOG_WARNING(...) \
   LOG(Log::_LogCurrentSinks, Log::LogLevel::LogWarn, __VA_ARGS__ << Log::endlog)

// A macro to log information in the set of sinks specified by AddSink and RemoveSink
#define LOG_INFO(...) \
   LOG(Log::_LogCurrentSinks, Log::LogLevel::LogInfo, __VA_ARGS__ << Log::endlog)

// A macro to log verbose information in the set of sinks specified by AddSink and RemoveSink
// at a specified verbosity. Under current configurations, this should be between 1 and 3 inclusive.
#define LOG_VERBOSE(VERBOSITY, ...) \
   LOG(Log::_LogCurrentSinks, Log::LogLevel::LogVerbose##VERBOSITY, __VA_ARGS__ << Log::endlog)

namespace Log {

	// A vector containing the set of sinks to be used when LOG_ERROR, LOG_WARNING, etc are used.
	// This vector is updated by the AddSink and RemoveSink functions.
	extern std::vector<std::reference_wrapper<LogSink>> _LogCurrentSinks;

	// A dummy class to indicate the termination of a log message.
	class LogTerminator {};

	// Indicates the end of a log message
	extern LogTerminator endlog;

	/**
	 * A class to handle log messages built around the style of a stream. The above macros are the
	 * preferred method of interracting with this class.
	 */
	class LogMessage {
		// The internal stream used to keep track of the log message
		std::stringstream InternalStream{};
		
		// The level at which the log message is being logged.
		LogLevel Level;

		// A vector containing the sinks to which this message is being logged.
		std::vector<std::reference_wrapper<LogSink>> Sinks{};

		/**
		 * An internal constructor used create a log message based off of an already existing
		 * stream.
		 */
		LogMessage(std::vector<std::reference_wrapper<LogSink>>, LogLevel, std::stringstream);

	public:

		/**
		 * Creates a log message at a given level and with a vector of sinks
		 *
		 * @param sinks The sinks that this message will log itself to.
		 * @param level The log level at which this message is logged.
		 */
		LogMessage(std::vector<std::reference_wrapper<LogSink>> sinks, LogLevel level);

		/**
		 * Creates a log message at a given level and with a sink
		 *
		 * @param sink The sink that this message will log itself to.
		 * @param level The log level at which this message is logged.
		 */
		LogMessage(LogSink& sink, LogLevel level);

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
		LogMessage& operator<<(const LogTerminator& termiantor);

		/**
		 * StringStreams don't support wide strings, so this serves as a handler for
		 * wide strings being logged.
		 *
		 * @param string The wide string to add to the message
		 *
		 * @return a reference to this log message.
		 */
		LogMessage& operator<<(const std::wstring string);

		/**
		 * StringStreams don't support wide strings, so this serves as a handler for
		 * wide strings being logged.
		 *
		 * @param string The wide string to add to the message
		 *
		 * @return a reference to this log message.
		 */
		LogMessage& operator<<(LPCWSTR pointer);

	private:

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
		LogMessage& InnerLog(T LogItem, std::false_type){
			InternalStream << LogItem;
			return *this;
		}

		/**
		 * At some point, it may become beneficial to log the current state of a component.
		 * This is meant to serve as a handler for components implementing the Loggable
		 * interface.
		 */
		LogMessage& InnerLog(Loggable& loggable, std::true_type){
			return operator<<(loggable.ToString());
		}

	public: 

		/**
		 * Tag dispatcher for the InnerLog functions
		 */
		template<class T>
		LogMessage& operator<<(T LogItem){
			return InnerLog(LogItem, std::is_base_of<Loggable, T>{});
		}
	};

	/**
	 * Adds a sink to the vector of default sinks to be used in LOG_ERROR, LOG_WARNING, etc.
	 * If the provided sink is equal to any sink in the vector already, this will return false
	 * and the sink will not be added.
	 *
	 * @param sink The sink to be added
	 *
	 * @return A boolean indicating whether or not the sink was added
	 */
	bool AddSink(LogSink& sink);

	/**
	 * Removes a sink from the vector of default sinks to be used in LOG_ERROR, LOG_WARNING, etc.
	 * If the provided sink is not equal to any sink in the vector already, this will return false
	 * and nothing will happen.
	 *
	 * @param sink The sink to be removed
	 *
	 * @return A boolean indicating whether or not the sink was removed
	 */
	bool RemoveSink(LogSink& sink);
}