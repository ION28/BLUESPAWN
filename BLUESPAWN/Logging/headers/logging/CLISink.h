#pragma once

#include <map>

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
		enum class MessageColor {
			BLACK     = 0x0,
			DARKBLUE  = 0x1,
			DARKGREEN = 0x2,
			CYAN      = 0x3,
			DARKRED   = 0x4,
			DARKPINK  = 0x5,
			GOLD      = 0x6,
			LIGHTGREY = 0x7,
			DARKGREY  = 0x8,
			BLUE      = 0x9,
			GREEN     = 0xA,
			LIGHTBLUE = 0xB,
			RED       = 0xC,
			PINK      = 0xD,
			YELLOW    = 0xE,
			WHITE     = 0xF
		};
		std::string MessagePrepends[4] = { "[ERROR]", "[WARNING]", "[INFO]", "[OTHER]" };
		MessageColor PrependColors[4] = { MessageColor::RED, MessageColor::YELLOW, MessageColor::BLUE, MessageColor::GREEN };

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

		/**
		 * Outputs a message to the console if its logging level is enabled. The log message
		 * is prepended with its severity level.
		 *
		 * @param level The level at which the message is being logged
		 * @param message The message to log
		 */
		virtual void LogMessage(LogLevel& level, std::string& message);

		/**
		 * Compares this CLISink to another LogSink. Currently, as only one console is supported,
		 * any other CLISink is considered to be equal. This is subject to change in the event that
		 * support for more consoles is added.
		 *
		 * @param sink The LogSink to compare
		 *
		 * @return Whether or not the argument and this sink are considered equal.
		 */
		virtual bool operator==(LogSink& sink);
	};
}
