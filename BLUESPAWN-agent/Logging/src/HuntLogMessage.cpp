#include "logging/HuntLogMessage.h"

#include "logging/LogLevel.h"

namespace Log {

	std::vector<std::reference_wrapper<LogSink>> _LogHuntSinks{};

	HuntLogMessage::HuntLogMessage(const HuntInfo& Hunt, std::vector<std::reference_wrapper<LogSink>> sinks) :
		LogMessage(sinks, LogLevel::LogHunt),
		HuntName{ Hunt }{}

	HuntLogMessage::HuntLogMessage(const HuntInfo& Hunt, const LogSink& sink) :
		LogMessage(sink, LogLevel::LogHunt),
		HuntName{ Hunt }{}

	void HuntLogMessage::AddDetection(DETECTION* detection){
		this->Detections.emplace_back(detection);
	}

	LogMessage& HuntLogMessage::operator<<(const LogTerminator& terminator){
		std::string message = InternalStream.str();

		InternalStream = std::stringstream();
		for(int idx = 0; idx < Sinks.size(); idx++){
			Sinks[idx].get().LogMessage(Level, message, HuntName, Detections);
		}
		return *this;
	}

	bool AddHuntSink(const LogSink& sink){
		for(int idx = 0; idx < _LogHuntSinks.size(); idx++){
			if(_LogHuntSinks[idx].get() == sink){
				return false;
			}
		}

		_LogHuntSinks.emplace_back(std::reference_wrapper<LogSink>(const_cast<LogSink&>(sink)));
		return true;
	}

	bool RemoveHuntSink(const LogSink& sink){
		for(int idx = 0; idx < _LogHuntSinks.size(); idx++){
			if(_LogHuntSinks[idx].get() == sink){
				_LogHuntSinks.erase(_LogHuntSinks.begin() + idx);
				return true;
			}
		}

		return false;
	}
}