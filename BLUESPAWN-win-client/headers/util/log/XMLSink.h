#pragma once

#include "../tinyxml2/tinyxml2.h"
#include "DetectionSink.h"
#include "LogSink.h"

namespace Log {

    /**
	 * XMLSink provides a sink for the logger that saves log messages to an XML file.
	 */
    class XMLSink : public LogSink, public DetectionSink {
        /// Guards access to the XML document
        CriticalSection hGuard;

        /// The XML document
        tinyxml2::XMLDocument XMLDoc;

        /// The root element in the XML document
        tinyxml2::XMLElement* Root;

        /// The element to which logs will be added
        tinyxml2::XMLElement* LogRoot;

        /// The name of the file to which the XML will be written
        std::wstring wFileName;

        /// Tags for messages sent at different levels
        std::string MessageTags[4] = { "error", "warning", "info", "other" };

        /// A handle to a thread that periodically flushes the log to the file
        HandleWrapper thread;

        /// A mapping of IDs to XML entries created for detections
        std::unordered_map<DWORD, tinyxml2::XMLElement*> detections;

        public:
        /**
		 * Default constructor for XMLSink. By default, the log will be saved to a file including the date and time in
		 * the name.
		 */
        XMLSink();

        /**
		 * Constructor for XMLSink. The log will be saved with the folder path passed as the argument
		 *
		 * @param wOutputDir The name of the folder to save the logs to.
		 */
        XMLSink(const std::wstring& wOutputDir);

        /**
		 * Constructor for XMLSink. The log will be saved with the folder path and name passed as the arguments
		 *
		 * @param wOutputDir The name of the folder to save the logs to.
		 * @param wFileName The name of the file to save the log as.
		 */
        XMLSink(const std::wstring& wOutputDir, const std::wstring& wFileName);

        /// Delete copy and move constructors and assignment operators
        XMLSink operator=(const XMLSink&) = delete;
        XMLSink operator=(XMLSink&&) = delete;
        XMLSink(const XMLSink&) = delete;
        XMLSink(XMLSink&&) = delete;

        /// Custom destructor
        ~XMLSink();

        /**
		 * Outputs a message to the debug console if its logging level is enabled. 
		 *
		 * @param level The level at which the message is being logged
		 * @param message The message to log
		 */
        virtual void LogMessage(const LogLevel& level, const std::wstring& message);

        /**
		 * Compares this XMLSink to another LogSink. All LogSink objects referring to the same file are considered 
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
		 * Records a detection to the XML document.
		 *
		 * @param detection The detection to record
		 * @param type The type of record this is, either PreScan or PostScan
		 */
        virtual void RecordDetection(IN CONST std::shared_ptr<Detection>& detection, IN RecordType type);

        /**
		 * Records an association between two detections to the XML document
		 *
		 * @param first The first detection in the assocation. This detection's ID will be lower than the second's.
		 * @param second The second detection in the association.
		 */
        virtual void RecordAssociation(IN CONST std::shared_ptr<Detection>& first,
                                       IN CONST std::shared_ptr<Detection>& second,
                                       IN CONST Association& strength);
    };
}   // namespace Log
