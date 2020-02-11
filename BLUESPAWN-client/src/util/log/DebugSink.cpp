#include <Windows.h>

#include <iostream>

#include "util/log/DebugSink.h"

namespace Log {
	void DebugSink::LogMessage(const LogLevel& level, const std::string& message, const std::optional<HuntInfo> info, 
		const std::vector<std::shared_ptr<DETECTION>>& detections){
		if(level.Enabled()){
			if(level.severity == Severity::LogHunt){
				std::wstring aggressiveness = info->HuntAggressiveness == Aggressiveness::Intensive ? L"Intensive" :
					info->HuntAggressiveness == Aggressiveness::Normal ? L"Normal" : L"Cursory";
				std::wstring sLogHeader = L"[" + info->HuntName + L": " + aggressiveness + L"] - ";
				OutputDebugStringW((sLogHeader + std::to_wstring(detections.size()) + L" detection" + (detections.size() == 1 ? L"!" : L"s!")).c_str());
				for(auto detection : detections){
					if(detection->Type == DetectionType::File){
						auto lpFileDetection = std::static_pointer_cast<FILE_DETECTION>(detection);
						OutputDebugStringW((sLogHeader + L"\tPotentially malicious file detected - " + lpFileDetection->wsFilePath).c_str());
					} else if(detection->Type == DetectionType::Process){
						auto lpProcessDetection = std::static_pointer_cast<PROCESS_DETECTION>(detection);
						OutputDebugStringW((sLogHeader + L"\tPotentially malicious process detected - " + lpProcessDetection->wsImageName + L" (PID is " + std::to_wstring(lpProcessDetection->PID) + L")").c_str());
					} else if(detection->Type == DetectionType::Service){
						auto lpServiceDetection = std::static_pointer_cast<SERVICE_DETECTION>(detection);
						OutputDebugStringW((sLogHeader + L"\tPotentially malicious service detected - " + lpServiceDetection->wsServiceName + L" (PID is " + std::to_wstring(lpServiceDetection->ServicePID) + L")").c_str());
					} else if(detection->Type == DetectionType::Registry){
						auto lpRegistryDetection = std::static_pointer_cast<REGISTRY_DETECTION>(detection);
						OutputDebugStringW((sLogHeader + L"\tPotentially malicious registry key detected - " + lpRegistryDetection->wsRegistryKeyPath + L": " + lpRegistryDetection->contents.wValueName + L" with value " + 
							lpRegistryDetection->contents.ToString()).c_str());
					} else {
						OutputDebugStringW((sLogHeader + L"\tUnknown detection type!").c_str());
					}
				}
				if(message.size() > 0){
					LPCSTR lpwMessage = message.c_str();
					LPWSTR lpMessage = new WCHAR[message.length() + 1]{};
					MultiByteToWideChar(CP_ACP, 0, lpwMessage, static_cast<int>(message.length()), lpMessage, static_cast<int>(message.length()));

					OutputDebugStringW((sLogHeader + L"\tAssociated Message: " + lpMessage).c_str());
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