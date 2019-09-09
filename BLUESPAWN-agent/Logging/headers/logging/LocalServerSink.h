#pragma once

#include <map>

#include "LogSink.h"
#include "LogLevel.h"
#include "../../React/Reactions/headers/reactions/Reaction.h"
# include <random>

namespace Log {

	/**
	 * LocalServerSink provides a sink for the logger that directs output to the console.
	 *
	 * Each log message is prepended with the severity of the log, as defined in
	 * MessagePrepends.
	 */
	class LocalServerSink : public LogSink {
	private:
		std::string MessagePrepends[4] = { "[ERROR]", "[WARNING]", "[INFO]", "[OTHER]" };
		bool hunting = false;
		std::string huntName;

	public:

		/**
		 * Outputs a string message to the network if its logging level is enabled. The log message
		 * is prepended with its severity level.
		 *
		 * @param level The level at which the message is being logged
		 * @param message The string message to log to the network
		 */
		virtual void LogMessage(LogLevel& level, std::string& message);

		void LogFileReaction(LogLevel& level, FILE_DETECTION* fileData, std::string& message);
		void LogRegistryReaction(LogLevel& level, REGISTRY_DETECTION* registryData, std::string& message);
		void LogProcessReaction(LogLevel& level, SERVICE_DETECTION* serviceData, std::string& message);
		void LogServiceReaction(LogLevel& level, PROCESS_DETECTION* processData, std::string& message);

		void StartHunt(std::string& huntName);
		void EndHunt();

		/**
		 * Compares this LocalServerSink to another LogSink.
		 *
		 * @param sink The LogSink to compare
		 * @return Whether or not the argument and this sink are considered equal.
		 */
		virtual bool operator==(LogSink& sink);
	};
}
