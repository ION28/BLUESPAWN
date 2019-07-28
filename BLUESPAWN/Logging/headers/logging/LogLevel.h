#include <string>
#include <functional>

#include "LogSink.h"


namespace Log {
	class LogLevel {
	private:
		std::function<void(LogSink& sink, std::string)> logger;
		LogLevel(std::function<void(LogSink& sink, std::string)> LogMethod);
	public:
		static const LogLevel
			LogError,
			LogWarn,
			LogInfo,
			LogVerbose1,
			LogVerbose2,
			LogVerbose3;

		void Log(LogSink& sink, std::string& message);
	};
}