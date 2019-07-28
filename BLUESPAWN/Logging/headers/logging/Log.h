#pragma once

#include <Windows.h>
#include <string>
#include <sstream>
#include <functional>
#include <vector>

#include "LogLevel.h"
#include "Loggable.h"
#include "LogSink.h"

#define LOG(SINK, LEVEL, ...) \
    Log::LogMessage(SINK, LEVEL) << __VA_ARGS__ 

#define LOG_ERROR(...) \
   LOG(Log::_LogCurrentSinks, Log::LogLevel::LogError, __VA_ARGS__ << Log::endlog)

#define LOG_WARNING(...) \
   LOG(Log::_LogCurrentSinks, Log::LogLevel::LogWarn, __VA_ARGS__ << Log::endlog)

#define LOG_INFO(...) \
   LOG(Log::_LogCurrentSinks, Log::LogLevel::LogInfo, __VA_ARGS__ << Log::endlog)

#define LOG_VERBOSE(VERBOSITY, ...) \
   LOG(Log::_LogCurrentSinks, Log::LogLevel::LogVerbose##VERBOSITY, __VA_ARGS__ << Log::endlog)

namespace Log {

	extern std::vector<std::reference_wrapper<LogSink>> _LogCurrentSinks;

	class LogTerminator {};

	extern LogTerminator endlog;

	class LogMessage {
		std::stringstream InternalStream{};
		
		LogLevel Level;
		std::vector<std::reference_wrapper<LogSink>> Sinks{};

		LogMessage(std::vector<std::reference_wrapper<LogSink>>, LogLevel, std::stringstream);

	public:

		LogMessage& operator<<(const std::wstring&);
		LogMessage& operator<<(PCWSTR pointer);
		LogMessage& operator<<(const LogTerminator&);
		LogMessage& operator<<(Loggable&);

		template<class T>
		LogMessage& operator<<(const T LogItem){
			InternalStream << LogItem;
			return *this;
		};

		LogMessage(std::vector<std::reference_wrapper<LogSink>>, LogLevel);
		LogMessage(LogSink&, LogLevel);
	};

	bool AddSink(LogSink&);

	bool RemoveSink(LogSink&);
}