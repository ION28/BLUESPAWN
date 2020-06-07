#include "util/log/LogLevel.h"

namespace Log {

	LogLevel::LogLevel(Severity severity) : enabled{ true }, severity{ severity } {}
	LogLevel::LogLevel(Severity severity, bool enabled) : enabled{ enabled }, severity{ severity } {}

	LogLevel LogLevel::LogError{Severity::LogError, true };

	LogLevel LogLevel::LogWarn{Severity::LogWarn, true };

	LogLevel LogLevel::LogInfo{ Severity::LogInfo, true };

	LogLevel LogLevel::LogHunt{ Severity::LogHunt, true };

	LogLevel LogLevel::LogVerbose1{ Severity::LogInfo, false };

	LogLevel LogLevel::LogVerbose2{ Severity::LogInfo, false };

	LogLevel LogLevel::LogVerbose3{ Severity::LogInfo, false };

	void LogLevel::Enable(){ enabled = true; }
	void LogLevel::Disable(){ enabled = false; }
	bool LogLevel::Toggle(){ return enabled = !enabled; }
	bool LogLevel::Enabled() const { return enabled; }
}