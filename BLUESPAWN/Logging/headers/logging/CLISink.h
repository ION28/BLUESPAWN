#pragma once

#include <map>

#include "LogSink.h"

namespace Log {
	class CLISink : public LogSink {
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
		MessageColor PrependColors[4] = { MessageColor::RED, MessageColor::YELLOW, MessageColor::LIGHTBLUE, MessageColor::GREEN };
		
		Mode CurrentMode = INFO_LOG;

		void SetConsoleColor(MessageColor color);

		virtual void SetMode(Mode m);
		virtual void LogMessage(std::string& message);
		virtual bool operator==(LogSink& sink);
	};
}
