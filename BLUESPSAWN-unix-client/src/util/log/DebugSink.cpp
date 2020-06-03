

#include <iostream>

#include "util/log/DebugSink.h"

namespace Log {
	void DebugSink::LogMessage(const LogLevel& level, const std::string& message, const std::optional<HuntInfo> info, 
		const std::vector<std::shared_ptr<DETECTION>>& detections){
		if(level.Enabled()){
			if(level.severity == Severity::LogHunt){
				std::string aggressiveness = info->HuntAggressiveness == Aggressiveness::Intensive ? "Intensive" :
					info->HuntAggressiveness == Aggressiveness::Normal ? "Normal" : "Cursory";
				std::string sLogHeader = "[" + info->HuntName + ": " + aggressiveness + "] - ";
				OutputDebugStringW((sLogHeader + std::to_string(detections.size()) + " detection" + (detections.size() == 1 ? "!" : "s!")).c_str());
				for(auto detection : detections){
					if(detection->Type == DetectionType::File){
						auto lpFileDetection = std::static_pointer_cast<FILE_DETECTION>(detection);
						OutputDebugStringW((sLogHeader + "\tPotentially malicious file detected - " + lpFileDetection->wsFilePath).c_str());
					} else if(detection->Type == DetectionType::Process){
						auto lpProcessDetection = std::static_pointer_cast<PROCESS_DETECTION>(detection);
						OutputDebugStringW((sLogHeader + "\tPotentially malicious process detected - " + lpProcessDetection->wsCmdline + " (PID is " + std::to_string(lpProcessDetection->PID) + ")").c_str());
					} else if(detection->Type == DetectionType::Service){
						auto lpServiceDetection = std::static_pointer_cast<SERVICE_DETECTION>(detection);
						OutputDebugStringW((sLogHeader + "\tPotentially malicious service detected - " + lpServiceDetection->wsServiceName + " (PID is " + std::to_string(lpServiceDetection->ServicePID) + ")").c_str());
					} else {
						OutputDebugStringW((sLogHeader + "\tUnknown detection type!").c_str());
					}
				}
				if(message.size() > 0){
					LPCSTR lpwMessage = message.c_str();
					LPWSTR lpMessage = new WCHAR[message.length() + 1]{};
					MultiByteToWideChar(CP_ACP, 0, lpwMessage, static_cast<int>(message.length()), lpMessage, static_cast<int>(message.length()));

					OutputDebugStringW((sLogHeader + "\tAssociated Message: " + lpMessage).c_str());
				}
			} else {
				OutputDebugStringA((DebugSink::MessagePrepends[static_cast<WORD>(level.severity)] + " " + message).c_str());
			}
		}
	}

	bool DebugSink::operator==(const LogSink& sink) const {
		return (bool) dynamic_cast<const DebugSink*>(&sink);
	}
}