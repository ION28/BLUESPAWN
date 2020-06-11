#pragma once

#include <Windows.h>

#include <string>
#include <optional>
#include <vector>

namespace Log {
	/**
	 * This denotes the severity of a log message. This is intended to be used by
	 * LogSinks to choose how to record a given log message.
	 */
	enum class Severity {
		LogError = 0,
		LogWarn = 1,
		LogInfo = 2,
		LogVerbose = 3
	};

	/**
	 * This indicates the level of detail in the log level.
	 */
	enum class Detail {
		Low = 0,
		Moderate = 1,
		High = 2
	};

	/// Forward declare log sink
	class LogSink;

	/**
	 * This class represents the "level" of a log message. This is similar to Severity
	 * in that it categorizes logs, but it's inteded to extend the functionality present
	 * in a manner that doesn't affect the log sinks by allowing the enabling or disabling
	 * of certain logging levels.
	 */
	class LogLevel {
	private:
		
		/// Whether or not sinks should record log messages under this level
		bool enabled;

		/// The sinks to which messages at this level will be recorded
		std::vector<LogSink*> sinks;

	public:
		/// The severity at which this log level operates
		const Severity severity;

		/// The level of detail present at this logging level
		const std::optional<Detail> detail;

		/// Default logging levels available, though custom ones can be created
		static LogLevel
			LogError,    // Intended for logging errors
			LogWarn,     // Intended for logging warnings
			LogInfo1,    // Intended for logging high level operational information
			LogInfo2,    // Intended for logging moderately detailed operational information
			LogInfo3,    // Intended for logging very detailed operational information
			LogVerbose1, // Intended for a low level of verbosity
			LogVerbose2, // Intended for a moderate level of verbosity
			LogVerbose3; // Intended for a high level of verbosity

		/**
		 * Creates a new log level, enabled by default, with a given severity.
		 * 
		 * @param severity The severity of messages under this logging level
		 * @param detail The level of detail present at this logging level
		 */
		LogLevel(
			IN Severity severity,
			IN CONST std::optional<Detail>& detail = std::nullopt OPTIONAL
		);

		/**
		 * Creates a new log level with a given severity.
		 *
		 * @param severity The severity of messages under this logging level
		 * @param DefaultState Indicates whether or not log messages should be recorded
		 *        by default when logged at this logging level.
		 */
		LogLevel(
			IN Severity severity, 
			IN bool DefaultState,
			IN CONST std::optional<Detail>& detail = std::nullopt OPTIONAL
		);

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
		bool Enabled() const;

		/**
		 * Adds a sink to which messages logged at this level are recorded. If the level already
		 * is logging to the sink, this has no effect.
		 *
		 * @param sink The sink to add 
		 */
		void AddSink(
			IN LogSink* sink
		);

		/**
		 * Logs the given message at this level in the sinks configured for this level
		 *
		 * @param message The message to log
		 */
		void LogMessage(
			IN CONST std::wstring& message
		);
	};
}