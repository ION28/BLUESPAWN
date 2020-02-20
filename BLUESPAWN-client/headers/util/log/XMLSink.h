#pragma once

#include "LogSink.h"
#include "../external/tinyxml2/tinyxml2.h"

namespace Log {

	/**
	 * XMLSink provides a sink for the logger that saves log messages to an XML file.
	 */
	class XMLSink : public LogSink {
		HandleWrapper hMutex;

		tinyxml2::XMLDocument XMLDoc;
		tinyxml2::XMLElement* Root;

		std::wstring wFileName;

		std::string MessageTags[5] = { "error", "warning", "info", "other", "hunt" };

	public:

		/**
		 * Default constructor for XMLSink. By default, the log will be saved to a file
		 * named bluespawn-MM-DD-YYYY-HHMM-SS.xml
		 */
		XMLSink();

		/**
		 * Constructor for XMLSink. The log will be saved with the name passed as the argument
		 *
		 * @param wFileName The name of the file to save the log as.
		 */
		XMLSink(const std::wstring& wFileName);

		XMLSink operator=(const XMLSink&) = delete;
		XMLSink operator=(XMLSink&&) = delete;
		XMLSink(const XMLSink&) = delete;
		XMLSink(XMLSink&&) = delete;

		~XMLSink();

		/**
		 * Outputs a message to the debug console if its logging level is enabled. The log message
		 * is prepended with its severity level.
		 *
		 * @param level The level at which the message is being logged
		 * @param message The message to log
		 */
		virtual void LogMessage(const LogLevel& level, const std::string& message, const std::optional<HuntInfo> info = std::nullopt,
			const std::vector<std::shared_ptr<DETECTION>>& detections = {});

		/**
		 * Compares this DebugSink to another LogSink. Currently, as only one debug console is supported,
		 * any other DebugSink is considered to be equal. This is subject to change in the event that
		 * support for more consoles is added.
		 *
		 * @param sink The LogSink to compare
		 *
		 * @return Whether or not the argument and this sink are considered equal.
		 */
		virtual bool operator==(const LogSink& sink) const;
	};
}