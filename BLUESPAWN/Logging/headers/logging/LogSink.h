#pragma once

#include <string>

namespace Log {
	class LogSink {
	public:
		enum Mode {
			ERROR_LOG   = 0, 
			WARNING_LOG = 1, 
			INFO_LOG    = 2, 
			UNKOWN_LOG  = 3
		};

		virtual void SetMode(Mode m) = 0;

		virtual void LogMessage(std::string& message) = 0;

		virtual bool operator==(LogSink& sink) = 0;
	};
}