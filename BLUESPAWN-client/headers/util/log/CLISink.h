#pragma once

#include <map>

#include "LogSink.h"
#include "LogLevel.h"
#include "DetectionSink.h"

namespace Log {

	/**
	 * CLISink provides a sink for the logger that directs output to the console.
	 * 
	 * Each log message is prepended with the severity of the log, as defined in MessagePrepends. This prepended text 
	 * is colored with the color indicated in PrependColors. 
	 */
	class CLISink : public LogSink, public DetectionSink {
	private:

		/// Enum containing color codes for console colors
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
			WHITE     = 0xF,
		};

		/// Prepends for messages
		std::wstring MessagePrepends[5] = { L"[ERROR]", L"[WARNING]", L"[INFO]", L"[VERBOSE]", L"[DETECTION]" };

		/// Colors for the message prepends
		MessageColor PrependColors[5] = { MessageColor::RED, MessageColor::YELLOW, MessageColor::BLUE, 
			MessageColor::LIGHTBLUE, MessageColor::GOLD };

		/// Mutex guarding accesses to the console
		HandleWrapper hMutex;

		/**
		 * Sets the color of text written to the console. The low order nibble is the color of the text, and the high 
		 * order nibble is the color of the background. Colors are defined in the MessageColor enum. Note that this 
		 * function is for internal use, and any external calls to it will be overridden by the next log message.
		 *
		 * @param color The color to set the console
		 */
		void SetConsoleColor(MessageColor color);

	public:

		CLISink();

		/**
		 * Outputs a message to the console if its logging level is enabled. The log message is prepended with its 
		 * severity level.
		 *
		 * @param level The level at which the message is being logged
		 * @param message The message to log
		 */
		virtual void LogMessage(
			IN CONST LogLevel& level, 
			IN CONST std::wstring& message
		) override;

		/**
		 * Compares this CLISink to another LogSink. Currently, as only one console is supported, any other CLISink is
		 * considered to be equal. This is subject to change in the event that support for more consoles is added.
		 *
		 * @param sink The LogSink to compare
		 *
		 * @return Whether or not the argument and this sink are considered equal.
		 */
		virtual bool operator==(
			IN CONST LogSink& sink
		) const;

		/**
		 * Updates the raw and combined certainty values associated with a detection
		 *
		 * @param detection The detection to update
		 */
		virtual void UpdateCertainty(
			IN CONST std::shared_ptr<Detection>& detection
		);

		/**
		 * Records a detection to the console.
		 *
		 * @param detection The detection to record
		 * @param type The type of record this is, either PreScan or PostScan
		 */
		virtual void RecordDetection(
			IN CONST std::shared_ptr<Detection>& detection,
			IN RecordType type
		);

		/**
		 * Records an association between two detections to the console
		 *
		 * @param first The first detection in the assocation. This detection's ID will be lower than the second's.
		 * @param second The second detection in the association.
		 * @param strength The strength of the connection
		 */
		virtual void RecordAssociation(
			IN CONST std::shared_ptr<Detection>& first,
			IN CONST std::shared_ptr<Detection>& second,
			IN CONST Association& strength
		);
	};
}
