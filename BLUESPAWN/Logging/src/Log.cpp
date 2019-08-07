#include "logging/Log.h"
#include <iostream>

namespace Log {
	std::vector<std::reference_wrapper<Log::LogSink>> _LogCurrentSinks; 
	LogTerminator endlog{};

	LogMessage& LogMessage::operator<<(const std::wstring message){
		LPCWSTR lpwMessage = message.c_str();
		LPSTR lpMessage = new CHAR[message.length() + 1]{};
		WideCharToMultiByte(CP_ACP, 0, lpwMessage, static_cast<int>(message.length()), lpMessage, static_cast<int>(message.length()), 0, nullptr);

		InternalStream << std::string(lpMessage);
		return *this;
	}
	LogMessage& LogMessage::operator<<(PCWSTR pointer){
		return operator<<(std::wstring(pointer));
	}
	LogMessage& LogMessage::operator<<(const LogTerminator& terminator){		
		std::string message = InternalStream.str();

		InternalStream = std::stringstream();
		for(int idx = 0; idx < Sinks.size(); idx++){
			Sinks[idx].get().LogMessage(Level, message);
		}
		return *this;
	}

	LogMessage::LogMessage(LogSink& Sink, LogLevel Level) : Level{ Level } {
		Sinks.emplace_back(Sink);
	}
	LogMessage::LogMessage(std::vector<std::reference_wrapper<LogSink>> Sinks, LogLevel Level) : LogMessage(Sinks, Level, std::stringstream{}) {}
	LogMessage::LogMessage(std::vector<std::reference_wrapper<LogSink>> Sinks, LogLevel Level, std::stringstream Stream) : Level{ Level } {
		this->Sinks = Sinks;
		std::string StreamContents = Stream.str();
		InternalStream << StreamContents;
	}

	bool AddSink(LogSink& sink){
		for(int idx = 0; idx < _LogCurrentSinks.size(); idx++){
			if(_LogCurrentSinks[idx].get() == sink){
				return false;
			}
		}

		_LogCurrentSinks.emplace_back(sink);
		return true;
	}

	bool RemoveSink(LogSink& sink){
		for(int idx = 0; idx < _LogCurrentSinks.size(); idx++){
			if(_LogCurrentSinks[idx].get() == sink){
				_LogCurrentSinks.erase(_LogCurrentSinks.begin() + idx);
				return true;
			}
		}

		return false;
	}
}
