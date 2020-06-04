#pragma once

#include <map>
#include <pthread.h>
#include "user/CLI.h"

#include "LogSink.h"
#include "LogLevel.h"

namespace Log {

	/**
	 * CLISink provides a sink for the logger that directs output to the console.
	 * 
	 * Each log message is prepended with the severity of the log, as defined in
	 * MessagePrepends. This prepended text is colored with the color indicated in
	 * PrependColors. 
	 */
	class CLISink : public LogSink {
	private:
		std::string MessagePrepends[4] = { "[ERROR]", "[WARNING]", "[INFO]", "[OTHER]" };
		MessageColor PrependColors[5] = { MessageColor::RED, MessageColor::YELLOW, MessageColor::BLUE, MessageColor::GREEN, MessageColor::CYAN }; //TODO: change other color?
		pthread_mutex_t hMutex;

		/**
		 * Sets the color of text written to the console. The low order nibble is the color
		 * of the text, and the high order nibble is the color of the background. Colors are
		 * defined in the MessageColor enum. Note that this function is for internal use, and
		 * any external calls to it will be overridden by the next log message.
		 *
		 * @param color The color to set the console
		 */
		void SetConsoleColor(MessageColor color);

	public:

		CLISink();

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
		 * Compares this CLISink to another LogSink. Currently, as only one console is supported,
		 * any other CLISink is considered to be equal. This is subject to change in the event that
		 * support for more consoles is added.
		 *
		 * @param sink The LogSink to compare
		 *
		 * @return Whether or not the argument and this sink are considered equal.
		 */
		virtual bool operator==(const LogSink& sink) const;
	};
}
