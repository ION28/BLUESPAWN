#pragma once

#include "util/rpc/RpcClient.h"

#include "DetectionSink.h"
#include "LogSink.h"

namespace Log {

    /**
	 * ServerSink provides a sink for the logger that will send logs to a remote server, usually a BLUESPAWN-server installation
	 */
    class ServerSink : public LogSink, public DetectionSink {
        /// Rpc Server Client
        RpcClient::RpcClient client;

        /// The remote server (http(s)://)IP:PORT or (http(s)://)FQDN:PORT that will recieve the logs
        std::string ServerAddress;

        /// Tags for messages sent at different levels
        std::string MessageTags[4] = { "error", "warning", "info", "other" };

        /// A set of IDs created for detections already sent to the server
        std::set<DWORD> detections;

        void AddAssociation(IN DWORD detection_id, IN DWORD associated, IN double strength);

        public:
        /**
		 * Default constructor for ServerSink. Must provide a server address to send the logs
		 */
        ServerSink(const std::string address);

        /**
		 * Outputs a message to the target server if its logging level is enabled. 
		 *
		 * @param level The level at which the message is being logged
		 * @param message The message to log
		 */
        virtual void LogMessage(const LogLevel& level, const std::wstring& message);

        /**
		 * Compares this ServerSink to another LogSink. All LogSink objects referring to the same file are considered 
		 * equal
		 *
		 * @param sink The LogSink to compare
		 *
		 * @return Whether or not the argument and this sink are considered equal.
		 */
        virtual bool operator==(const LogSink& sink) const;

        /**
		 * Updates the raw and combined certainty values associated with a detection
		 * 
		 * @param detection The detection to update
		 */
        virtual void UpdateCertainty(IN CONST std::shared_ptr<Detection>& detection);

        /**
		 * Records a detection, sending the information to the server.
		 *
		 * @param detection The detection to record
		 * @param type The type of record this is, either PreScan or PostScan
		 */
        virtual void RecordDetection(IN CONST std::shared_ptr<Detection>& detection, IN RecordType type);

        /**
		 * Records an association between two detections and informs the server
		 *
		 * @param first The first detection in the assocation. This detection's ID will be lower than the second's.
		 * @param second The second detection in the association.
		 */
        virtual void RecordAssociation(IN CONST std::shared_ptr<Detection>& first,
                                       IN CONST std::shared_ptr<Detection>& second,
                                       IN CONST Association& strength);
    };
}   // namespace Log
