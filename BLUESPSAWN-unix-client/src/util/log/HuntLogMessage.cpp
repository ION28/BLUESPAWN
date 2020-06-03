#include "util/log/HuntLogMessage.h"

#include "util/log/LogLevel.h"

namespace Log {

	std::vector<std::shared_ptr<LogSink>> _LogHuntSinks{};

	HuntLogMessage::HuntLogMessage(const HuntInfo& Hunt, const std::vector<std::shared_ptr<LogSink>>& sinks) :
		LogMessage(sinks, LogLevel::LogHunt),
		HuntName{ Hunt },
		Detections{}{}

	HuntLogMessage::HuntLogMessage(const HuntInfo& Hunt, const std::shared_ptr<LogSink>& sink) :
		LogMessage(sink, LogLevel::LogHunt),
		HuntName{ Hunt },
		Detections{}{}

	void HuntLogMessage::AddDetection(std::shared_ptr<DETECTION> detection){
		this->Detections.emplace_back(detection);
	}

	LogMessage& HuntLogMessage::operator<<(const LogTerminator& terminator){
		std::string message = InternalStream.str();

		InternalStream.str(std::string{});
		for(int idx = 0; idx < Sinks.size(); idx++){
			Sinks[idx]->LogMessage(Level, message, HuntName, Detections);
		}

		Detections = {};

		return *this;
	}

	bool AddHuntSink(const std::shared_ptr<LogSink>& sink){
		for(int idx = 0; idx < _LogHuntSinks.size(); idx++){
			if(*_LogHuntSinks[idx] == *sink){
				return false;
			}
		}

		_LogHuntSinks.emplace_back(sink);
		return true;
	}

	bool RemoveHuntSink(const std::shared_ptr<LogSink>& sink){
		for(int idx = 0; idx < _LogHuntSinks.size(); idx++){
			if(*_LogHuntSinks[idx] == *sink){
				_LogHuntSinks.erase(_LogHuntSinks.begin() + idx);
				return true;
			}
		}

		return false;
	}

	HuntLogMessage HuntLogMessage::operator =(const HuntLogMessage& message){
		this->HuntName = message.HuntName;
		this->InternalStream << message.InternalStream.str();
		this->Sinks = message.Sinks;
		this->Detections = message.Detections;

		return *this;
	}

	HuntLogMessage::HuntLogMessage(const HuntLogMessage& message) :
		LogMessage{ message.Sinks, message.Level },
		HuntName{ message.HuntName }{
		this->InternalStream << message.InternalStream.str();
		this->HuntName = message.HuntName;
		this->Detections = message.Detections;
	}
}