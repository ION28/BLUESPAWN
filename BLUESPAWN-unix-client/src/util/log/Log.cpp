#include "util/log/Log.h"
#include "common/StringUtils.h"
#include <iostream>

namespace Log {
	std::vector<std::shared_ptr<Log::LogSink>> _LogCurrentSinks; 
	LogTerminator endlog{};


	LogMessage& LogMessage::operator<<(const std::string& message){
		InternalStream << std::string(message);
		return *this;
	}

	LogMessage& LogMessage::operator<<(char * pointer){
		return operator<<(std::string(pointer));
	}

	LogMessage& LogMessage::operator<<(const std::wstring& message){
		return operator<<(WidestringToString(message));
	}
	LogMessage& LogMessage::operator<<(const LogTerminator& terminator){
		std::string message = InternalStream.str();

		InternalStream = std::stringstream();
		for(int idx = 0; idx < Sinks.size(); idx++){
			Sinks[idx]->LogMessage(Level, message);
		}
		return *this;
	}

	LogMessage::LogMessage(const std::shared_ptr<LogSink>& Sink, LogLevel Level) : Level{ Level } {
		Sinks.emplace_back(Sink);
	}
	LogMessage::LogMessage(std::vector<std::shared_ptr<LogSink>> Sinks, LogLevel Level) : LogMessage(Sinks, Level, std::stringstream{}) {}
	LogMessage::LogMessage(std::vector<std::shared_ptr<LogSink>> Sinks, LogLevel Level, std::stringstream Stream) : Level{ Level } {
		this->Sinks = Sinks;
		std::string StreamContents = Stream.str();
		InternalStream << StreamContents;
	}

	bool AddSink(const std::shared_ptr<LogSink>& Sink){
		for(int idx = 0; idx < _LogCurrentSinks.size(); idx++){
			if(*_LogCurrentSinks[idx] == *Sink){
				return false;
			}
		}

		_LogCurrentSinks.emplace_back(Sink);
		return true;
	}

	bool RemoveSink(const std::shared_ptr<LogSink>& Sink){
		for(int idx = 0; idx < _LogCurrentSinks.size(); idx++){
			if(*_LogCurrentSinks[idx] == *Sink){
				_LogCurrentSinks.erase(_LogCurrentSinks.begin() + idx);
				return true;
			}
		}

		return false;
	}

	std::string FormatErrorMessage(unsigned int dwErrorCode) {
		return std::string(strerror(dwErrorCode));
	}
}
