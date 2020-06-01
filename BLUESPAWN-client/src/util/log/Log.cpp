#include "util/log/Log.h"
#include <iostream>

#include "common/StringUtils.h"

namespace Log {
	std::vector<std::unique_ptr<Log::LogSink>> _LogSinks; 
	LogTerminator endlog{};

	LogMessage& LogMessage::operator<<(IN CONST LogTerminator& terminator){
		auto message{ stream.str() };

		stream = std::wstringstream{};
		level.LogMessage(message);

		return *this;
	}

	LogMessage& LogMessage::InnerLog(IN CONST Loggable& loggable,
									 IN CONST std::true_type&){
		return operator<<(loggable.ToString());
	}

	template<>
	LogMessage& LogMessage::InnerLog(IN CONST LPCSTR& data,
									 IN CONST std::false_type&){
		stream << StringToWidestring(data);
	}

	template<>
	LogMessage& LogMessage::InnerLog(IN CONST std::string& data,
									 IN CONST std::false_type&){
		stream << StringToWidestring(data);
	}

	LogMessage::LogMessage(IN CONST LogLevel& level) : level{ level } {}
	LogMessage::LogMessage(IN CONST LogLevel& level,
						   IN CONST std::wstringstream& message) :
		level{ level },
		stream{}{
		stream << message.str();
	}

	void AddSink(IN std::unique_ptr<LogSink>&& sink,
				 IN CONST std::vector<std::reference_wrapper<LogLevel>>& levels){
		LogSink* pointer{ sink.get() };
		bool exists{ false };

		for(auto& existing : _LogSinks){
			if(*existing == *sink){
				pointer = existing.get();
				exists = true;
			}
		}

		if(!exists){
			_LogSinks.emplace_back(std::move(sink));
		}

		for(auto level : levels){
			level.get().AddSink(pointer);
		}
	}
}
