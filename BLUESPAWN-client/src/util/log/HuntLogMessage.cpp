#include "util/log/HuntLogMessage.h"

#include "util/log/LogLevel.h"

namespace Log {

	std::vector<std::reference_wrapper<LogSink>> _LogHuntSinks{};

	HuntLogMessage::HuntLogMessage(const HuntInfo& Hunt, std::vector<std::reference_wrapper<LogSink>> sinks) :
		LogMessage(sinks, LogLevel::LogHunt),
		HuntName{ Hunt },
		Detections{}{}

	HuntLogMessage::HuntLogMessage(const HuntInfo& Hunt, const LogSink& sink) :
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
			Sinks[idx].get().LogMessage(Level, message, HuntName, Detections);
		}

		Detections = {};

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

	HuntLogMessage HuntLogMessage::operator =(const HuntLogMessage& message){
		this->HuntName = message.HuntName;
		this->InternalStream << message.InternalStream.str();
		this->Sinks = message.Sinks;
		this->Detections = message.Detections;

		return *this;
	}

	HuntLogMessage::HuntLogMessage(const HuntLogMessage& message) :
		LogMessage{ message.Sinks, message.Level }
	{
		this->InternalStream << message.InternalStream.str();
		this->HuntName = message.HuntName;
		this->Detections = message.Detections;
	}
}