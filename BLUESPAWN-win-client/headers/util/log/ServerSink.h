#pragma once

#include <nlohmann/json.hpp>

#include "DetectionSink.h"
#include "LogSink.h"

using json = nlohmann::json;

namespace Log {

    /**
	 * ServerSink provides a sink for the logger that will send logs to a remote server, usually a BLUESPAWN-server installation
	 */
    class ServerSink : public LogSink, public DetectionSink {
        /// Guards access to the server
        CriticalSection hGuard;

        /// The remote server (http(s)://)IP:PORT or (http(s)://)FQDN:PORT that will recieve the logs
        std::wstring wServerAddress;

        /// Tags for messages sent at different levels
        std::string MessageTags[4] = { "error", "warning", "info", "other" };

        /// A handle to a thread that periodically flushes the log to the file
        HandleWrapper thread;

        /// A set of IDs created for detections already sent to the server
        std::set<DWORD> detections;

        void AddAssociation(IN DWORD detection_id, IN DWORD associated, IN double strength);

        public:
        /**
		 * Default constructor for ServerSink. Must provide a server address to send the logs
		 */
        ServerSink(const std::wstring ServerAddress);

        /// Delete copy and move constructors and assignment operators
        ServerSink operator=(const ServerSink&) = delete;
        ServerSink operator=(ServerSink&&) = delete;
        ServerSink(const ServerSink&) = delete;
        ServerSink(ServerSink&&) = delete;

        /// Custom destructor
        ~ServerSink();

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
		 * Flushes the log to the server.
		*/
        void Flush();

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
