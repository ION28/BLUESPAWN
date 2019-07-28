#include "logging/LogLevel.h"

namespace Log{
	LogLevel::LogLevel(std::function<void(LogSink& sink, std::string)> logger) : logger{ logger }{}

	void LogLevel::Log(LogSink& sink, std::string& message){
		logger(sink, message);
	}

	const LogLevel LogLevel::LogError{ [](LogSink& sink, std::string message) {
		sink.SetMode(LogSink::ERROR_LOG);

		sink.LogMessage(message);
	} };

	const LogLevel LogLevel::LogWarn{ [](LogSink& sink, std::string message) {
		sink.SetMode(LogSink::WARNING_LOG);

		sink.LogMessage(message);
	} };

	const LogLevel LogLevel::LogInfo{ [](LogSink& sink, std::string message) {
		sink.SetMode(LogSink::INFO_LOG);

		sink.LogMessage(message);
	} };

	const LogLevel LogLevel::LogVerbose1{ LogInfo };

	const LogLevel LogLevel::LogVerbose2{ LogInfo };

	const LogLevel LogLevel::LogVerbose3{ LogInfo };
}