#include "util/log/LogLevel.h"
#include "util/log/LogSink.h"

namespace Log {

	LogLevel::LogLevel(IN Severity severity,
					   IN CONST std::optional<Detail>& detail OPTIONAL) :
		enabled{ true },
		severity{ severity },
		detail{ detail }{}
	LogLevel::LogLevel(IN Severity severity,
					   IN bool DefaultState,
					   IN CONST std::optional<Detail>& detail OPTIONAL) :
		enabled{ enabled },
		severity{ severity },
		detail{ detail }{}

	std::unique_ptr<LogLevel> LogLevel::LogError = std::make_unique<LogLevel>(Severity::LogError, true);
	std::unique_ptr<LogLevel> LogLevel::LogWarn = std::make_unique<LogLevel>(Severity::LogWarn, true);
	std::unique_ptr<LogLevel> LogLevel::LogInfo1 = std::make_unique<LogLevel>(Severity::LogInfo, true, Detail::Low);
	std::unique_ptr<LogLevel> LogLevel::LogInfo2 = std::make_unique<LogLevel>(Severity::LogInfo, false, Detail::Moderate);
	std::unique_ptr<LogLevel> LogLevel::LogInfo3 = std::make_unique<LogLevel>(Severity::LogInfo, false, Detail::High);
	std::unique_ptr<LogLevel> LogLevel::LogVerbose1 = std::make_unique<LogLevel>(Severity::LogVerbose, false, Detail::Low);
	std::unique_ptr<LogLevel> LogLevel::LogVerbose2 = std::make_unique<LogLevel>(Severity::LogVerbose, false, Detail::Moderate);
	std::unique_ptr<LogLevel> LogLevel::LogVerbose3 = std::make_unique<LogLevel>(Severity::LogVerbose, false, Detail::High);

	void LogLevel::Enable(){ enabled = true; }
	void LogLevel::Disable(){ enabled = false; }
	bool LogLevel::Toggle(){ return enabled = !enabled; }
	bool LogLevel::Enabled() const { return enabled; }

	void LogLevel::AddSink(IN LogSink* sink){
		for(auto existing : sinks){
			if(*existing == *sink){
				return;
			}
		}

		sinks.emplace_back(sink);
	}

	void LogLevel::LogMessage(IN CONST std::wstring& message){
		if(enabled){
			for(auto sink : sinks){
				sink->LogMessage(*this, message);
			}
		}
	}
}