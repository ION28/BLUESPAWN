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

	LogLevel LogLevel::LogError{Severity::LogError, true };

	LogLevel LogLevel::LogWarn{Severity::LogWarn, true };

	LogLevel LogLevel::LogInfo1{ Severity::LogInfo, true, Detail::Low };

	LogLevel LogLevel::LogInfo2{ Severity::LogInfo, false, Detail::Moderate };

	LogLevel LogLevel::LogInfo3{ Severity::LogInfo, false, Detail::High };

	LogLevel LogLevel::LogVerbose1{ Severity::LogVerbose, false, Detail::Low };

	LogLevel LogLevel::LogVerbose2{ Severity::LogVerbose, false, Detail::Moderate };

	LogLevel LogLevel::LogVerbose3{ Severity::LogVerbose, false, Detail::High };

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