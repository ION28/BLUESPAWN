#include "logging/LogLevel.h"

namespace Log {

	LogLevel::LogLevel(Severity severity) : enabled{ true }, severity{ severity } {}
	LogLevel::LogLevel(Severity severity, bool enabled) : enabled{ enabled }, severity{ severity } {}

	const LogLevel LogLevel::LogError{Severity::LogError, true };

	const LogLevel LogLevel::LogWarn{Severity::LogWarn, true };

	const LogLevel LogLevel::LogInfo{ Severity::LogInfo, true };

	const LogLevel LogLevel::LogVerbose1{ Severity::LogInfo, false };

	const LogLevel LogLevel::LogVerbose2{ Severity::LogInfo, false };

	const LogLevel LogLevel::LogVerbose3{ Severity::LogInfo, false };

	void LogLevel::Enable(){ enabled = true; }
	void LogLevel::Disable(){ enabled = true; }
	bool LogLevel::Toggle(){ return enabled = !enabled; }
	bool LogLevel::Enabled(){ return enabled; }
}