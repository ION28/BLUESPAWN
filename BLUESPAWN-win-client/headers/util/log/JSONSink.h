#pragma once

#include <nlohmann/json.hpp>

#include "DetectionSink.h"
#include "LogSink.h"

using json = nlohmann::json;

namespace Log {

    /**
	 * JSONSink provides a sink for the logger that saves log messages to an JSON file.
	 */
    class JSONSink : public LogSink, public DetectionSink {
        /// Guards access to the JSON document
        CriticalSection hGuard;

        /// The JSON document
        json JSONDoc;

        /// The root element in the JSON document
        json Root;

        /// The element to which logs will be added
        json LogRoot;

        /// The name of the file to which the JSON will be written
        std::wstring wFileName;

        /// Tags for messages sent at different levels
        std::string MessageTags[4] = { "error", "warning", "info", "other" };

        /// A handle to a thread that periodically flushes the log to the file
        HandleWrapper thread;

        /// A set of IDs created for detections already in the JSON
        std::set<DWORD> detections;

        /* 
        * This private function is called by RecordAssociation to update the JSON of 
        * detections to reflect a link between two detections.
        */
        void AddAssociation(IN DWORD detection_id, IN DWORD associated, IN double strength);

        void JSONSink::InsertElement(IN json JSONDoc,
                                     IN json parent,
                                     IN CONST std::string& name,
                                     IN CONST std::wstring& value);

        public:
        /**
		 * Default constructor for JSONSink. By default, the log will be saved to a file including the date and time in
		 * the name.
		 */
        JSONSink();

        /**
		 * Constructor for JSONSink. The log will be saved to the folder passed as the argument
		 *
		 * @param wOutputDir The folder to save the log to.
		 */
        JSONSink(const std::wstring& wOutputDir);

        /**
		 * Constructor for JSONSink. The log will be saved to the folder\name passed as the arguments
		 *
		 * @param wOutputDir The folder to save the log to.
		 * @param wFileName The name of the file to save the log as.
		 */
        JSONSink(const std::wstring& wOutputDir, const std::wstring& wFileName);

        /// Delete copy and move constructors and assignment operators
        JSONSink operator=(const JSONSink&) = delete;
        JSONSink operator=(JSONSink&&) = delete;
        JSONSink(const JSONSink&) = delete;
        JSONSink(JSONSink&&) = delete;

        /// Custom destructor
        ~JSONSink();

        /**
		 * Outputs a message to the debug console if its logging level is enabled. 
		 *
		 * @param level The level at which the message is being logged
		 * @param message The message to log
		 */
        virtual void LogMessage(const LogLevel& level, const std::wstring& message);

        /**
		 * Compares this JSONSink to another LogSink. All LogSink objects referring to the same file are considered 
		 * equal
		 *
		 * @param sink The LogSink to compare
		 *
		 * @return Whether or not the argument and this sink are considered equal.
		 */
        virtual bool operator==(const LogSink& sink) const;

        /**
		 * Flushes the log to the file.
		 */
        void Flush();

        /**
		 * Updates the raw and combined certainty values associated with a detection
		 * 
		 * @param detection The detection to update
		 */
        virtual void UpdateCertainty(IN CONST std::shared_ptr<Detection>& detection);

        /**
		 * Records a detection to the JSON document.
		 *
		 * @param detection The detection to record
		 * @param type The type of record this is, either PreScan or PostScan
		 */
        virtual void RecordDetection(IN CONST std::shared_ptr<Detection>& detection, IN RecordType type);

        /**
		 * Records an association between two detections to the JSON document
		 *
		 * @param first The first detection in the assocation. This detection's ID will be lower than the second's.
		 * @param second The second detection in the association.
		 */
        virtual void RecordAssociation(IN CONST std::shared_ptr<Detection>& first,
                                       IN CONST std::shared_ptr<Detection>& second,
                                       IN CONST Association& strength);
    };
}   // namespace Log
