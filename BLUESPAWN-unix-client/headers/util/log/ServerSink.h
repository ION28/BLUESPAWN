#pragma once

// Remove this once GRPC is fixed
#define GRPC_BROKEN

#ifndef GRPC_BROKEN
#include <map>

#include "LogSink.h"
#include "LogLevel.h"
#include "ReactionData.pb.h"
#include "reaction/Detections.h"

namespace Log {

	/**
	 * ServerSink provides a sink for the logger that directs output to the console.
	 * 
	 * Each log message is prepended with the severity of the log, as defined in
	 * MessagePrepends. This prepended text is colored with the color indicated in
	 * PrependColors. 
	 */
	class ServerSink : public LogSink {
	private:
		std::string MessagePrepends[4] = { "[ERROR]", "[WARNING]", "[INFO]", "[OTHER]" };

		// Converting HuntInfo to gpb::HuntInfo
		gpb::Aggressiveness HuntAggressivenessToGPB(const Aggressiveness& info);
		std::vector<gpb::Tactic> HuntTacticsToGPB(unsigned int info);
		std::vector<gpb::Category> HuntCategoriesToGPB(unsigned int info);
		std::vector<gpb::DataSource> HuntDatasourcesToGPB(unsigned int info);
		gpb::HuntInfo HuntInfoToGPB(const HuntInfo& info);

		std::vector<gpb::FileReactionData> GetFileReactions(const std::vector<std::shared_ptr<DETECTION>>& detections);
		std::vector<gpb::RegistryReactionData> GetRegistryReactions(const std::vector<std::shared_ptr<DETECTION>>& detections);
		std::vector<gpb::ProcessReactionData> GetProcessReactions(const std::vector<std::shared_ptr<DETECTION>>& detections);
		std::vector<gpb::ServiceReactionData> GetServiceReactions(const std::vector<std::shared_ptr<DETECTION>>& detections);

	public:

		/**
		 * Outputs a message to the console if its logging level is enabled. The log message
		 * is prepended with its severity level.
		 *
		 * @param level The level at which the message is being logged
		 * @param message The message to log
		 */
		virtual void LogMessage(const LogLevel& level, const std::string& message, const std::optional<HuntInfo> info = std::nullopt, 
			                    const std::vector<std::shared_ptr<DETECTION>>& detections = {}) override;

		/**
		 * Compares this ServerSink to another LogSink. Currently, as only one console is supported,
		 * any other ServerSink is considered to be equal. This is subject to change in the event that
		 * support for more consoles is added.
		 *
		 * @param sink The LogSink to compare
		 *
		 * @return Whether or not the argument and this sink are considered equal.
		 */
		virtual bool operator==(const LogSink& sink) const;
	};
}
#endif