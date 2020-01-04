#include "util/log/MitigationLogMessage.h"

#include "util/log/LogLevel.h"

namespace Log {

	std::vector<std::reference_wrapper<LogSink>> _LogMitigationSinks{};

	MitigationLogMessage::MitigationLogMessage(const std::vector<std::reference_wrapper<LogSink>>& sinks) :
		LogMessage(sinks, LogLevel::LogHunt),
		Detections{}{}

	MitigationLogMessage::MitigationLogMessage(const LogSink& sink) :
		LogMessage(sink, LogLevel::LogHunt),
		Detections{}{}

	void MitigationLogMessage::AddDetection(std::shared_ptr<DETECTION> detection){
		this->Detections.emplace_back(detection);
	}

	LogMessage& MitigationLogMessage::operator<<(const LogTerminator& terminator){
		std::string message = InternalStream.str();

		InternalStream.str(std::string{});
		for(int idx = 0; idx < Sinks.size(); idx++){
			//Sinks[idx].get().LogMessage(Level, message, "Placeholder", Detections);
		}

		Detections = {};

		return *this;
	}

	bool AddMitigationSink(const LogSink& sink){
		for(int idx = 0; idx < _LogMitigationSinks.size(); idx++){
			if(_LogMitigationSinks[idx].get() == sink){
				return false;
			}
		}

		_LogMitigationSinks.emplace_back(std::reference_wrapper<LogSink>(const_cast<LogSink&>(sink)));
		return true;
	}

	bool RemoveMitigationtSink(const LogSink& sink){
		for(int idx = 0; idx < _LogMitigationSinks.size(); idx++){
			if(_LogMitigationSinks[idx].get() == sink){
				_LogMitigationSinks.erase(_LogMitigationSinks.begin() + idx);
				return true;
			}
		}

		return false;
	}

	MitigationLogMessage MitigationLogMessage::operator =(const MitigationLogMessage& message){
		this->InternalStream << message.InternalStream.str();
		this->Sinks = message.Sinks;
		this->Detections = message.Detections;

		return *this;
	}

	MitigationLogMessage::MitigationLogMessage(const MitigationLogMessage& message) :
		LogMessage{ message.Sinks, message.Level }{
		this->InternalStream << message.InternalStream.str();
		this->Detections = message.Detections;
	}
}