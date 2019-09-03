#pragma once
namespace Log {
	/**
	 * This denotes the severity of a log message. This is intended to be used by
	 * LogSinks to choose how to record a given log message.
	 */
	enum class Severity {
		LogError = 0,
		LogWarn = 1,
		LogInfo = 2,
		LogOther = 3
	};

	/**
	 * This class represents the "level" of a log message. This is similar to Severity
	 * in that it categorizes logs, but it's inteded to extend the functionality present
	 * in a manner that doesn't affect the log sinks by allowing the enabling or disabling
	 * of certain logging levels.
	 */
	class LogLevel {
	private:
		// Whether or not sinks should record log messages under this level
		bool enabled;

	public:
		// The severity at which this log level operates
		const Severity severity;

		// Default logging levels available, though custom ones can be created
		static const LogLevel
			LogError,    // Intended for logging errors
			LogWarn,     // Intended for logging warnings
			LogInfo,     // Intended for logging information and statuses of hunts
			LogVerbose1, // Intended for a low level of verbosity
			LogVerbose2, // Intended for a moderate level of verbosity
			LogVerbose3; // Intended for a high level of verbosity

		/**
		 * Creates a new log level, enabled by default, with a given severity.
		 * 
		 * @param severity The severity of messages under this logging level
		 */
		LogLevel(Severity severity);

		/**
		 * Creates a new log level with a given severity.
		 *
		 * @param severity The severity of messages under this logging level
		 * @param DefaultState Indicates whether or not log messages should be recorded
		 *        by default when logged at this logging level.
		 */
		LogLevel(Severity severity, bool DefaultState);

		/**
		 * Enables logging at this level
		 */
		void Enable();

		/**
		 * Disables logging at this level
		 */
		void Disable();

		/**
		 * Toggles logging at this level
		 */
		bool Toggle();

		/**
		 * Indicates whether or not this log level is enabled.
		 *
		 * @return A boolean indicating whether or not log messages at this level should
		 *       be recorded.
		 */
		bool Enabled();
	};
}