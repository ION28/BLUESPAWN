#pragma once

#include <string>

#include "LogLevel.h"

namespace Log {
	class LogSink {
	public:
		virtual void LogMessage(LogLevel& level, std::string& message) = 0;

		virtual bool operator==(LogSink& sink) = 0;
	};
}