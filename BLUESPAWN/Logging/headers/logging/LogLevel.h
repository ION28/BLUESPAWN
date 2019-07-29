#pragma once
namespace Log {
	enum class Severity {
		LogError = 0,
		LogWarn = 1,
		LogInfo = 2,
		LogOther = 3
	};

	class LogLevel {
	private:
		bool enabled;

	public:
		const Severity severity;

		static const LogLevel
			LogError,
			LogWarn,
			LogInfo,
			LogVerbose1,
			LogVerbose2,
			LogVerbose3;

		LogLevel(Severity severity);
		LogLevel(Severity severity, bool DefaultState);

		void Enable();
		void Disable();
		bool Toggle();

		bool Enabled();
	};
}