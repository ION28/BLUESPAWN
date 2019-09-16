#include <Windows.h>

#include <iostream>

#include "logging/ServerSink.h"

namespace Log {

	void ServerSink::LogMessage(const LogLevel& level, const std::string& message, const HuntInfo& info, const std::vector<DETECTION*>& detections){
		if (!level.Enabled())
			return;

		HuntMessage huntMessage();

		if(level.severity == Severity::LogHunt){
			std::wstring aggressiveness = info.HuntAggressiveness == Aggressiveness::Aggressive ? L"Aggressive" :
				info.HuntAggressiveness == Aggressiveness::Careful ? L"Careful" :
				info.HuntAggressiveness == Aggressiveness::Moderate ? L"Moderate" : L"Cursory";
			std::wcout << L"[" << info.HuntName << L": " << aggressiveness << L"] ";
			std::wcout << L" - " << detections.size() << " detection" << (detections.size() == 1 ? L"" : L"s") << L"!" << std::endl;
			for(auto detection : detections){
				if(detection->DetectionType == DetectionType::File){
					auto* lpFileDetection = reinterpret_cast<FILE_DETECTION*>(detection); 
					std::wcout << L"\tPotentially malicious file detected - " << lpFileDetection->wsFileName << L" (hash is " << lpFileDetection->hash << L")" << std::endl;
				} else if(detection->DetectionType == DetectionType::Process){
					auto* lpProcessDetection = reinterpret_cast<PROCESS_DETECTION*>(detection);
					std::wcout << L"\tPotentially malicious process detected - " << lpProcessDetection->wsImageName << L" (PID is " << lpProcessDetection->PID << L")" << std::endl;
				} else if(detection->DetectionType == DetectionType::Service){
					auto* lpServiceDetection = reinterpret_cast<SERVICE_DETECTION*>(detection);
					std::wcout << L"\tPotentially malicious service detected - " << lpServiceDetection->wsServiceName << L" (PID is " << lpServiceDetection->ServicePID << L")" << std::endl;
				} else if(detection->DetectionType == DetectionType::Registry){
					auto* lpRegistryDetection = reinterpret_cast<REGISTRY_DETECTION*>(detection);
					std::wcout << L"\tPotentially malicious registry key detected - " << lpRegistryDetection->wsRegistryKeyPath << (lpRegistryDetection->wsRegistryKeyValue.length() ? L": " : L"") << lpRegistryDetection->wsRegistryKeyValue << std::endl;
				} else {
					std::wcout << L"\tUnknown detection type!" << std::endl;
				}
			}
			if(message.size() > 0){
				std::cout << "\tAssociated Message: " << message << std::endl;
			}
		} else {
			std::cout << ServerSink::MessagePrepends[static_cast<WORD>(level.severity)] << " ";
			std::cout << message << std::endl;
		}
	}

	bool ServerSink::operator==(const LogSink& sink) const {
		return (bool) dynamic_cast<const ServerSink*>(&sink);
	}
}