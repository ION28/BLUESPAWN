#include <Windows.h>

#include <iostream>

#include "util/log/CLISink.h"

namespace Log {

	void CLISink::SetConsoleColor(CLISink::MessageColor color){
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(hConsole, static_cast<WORD>(color));
	}

	void CLISink::LogMessage(const LogLevel& level, const std::string& message, const HuntInfo& info, const std::vector<std::shared_ptr<DETECTION>>& detections){
		if(level.Enabled()){
			SetConsoleColor(CLISink::PrependColors[static_cast<WORD>(level.severity)]);

			if(level.severity == Severity::LogHunt){
				std::wstring aggressiveness = info.HuntAggressiveness == Aggressiveness::Aggressive ? L"Aggressive" :
					info.HuntAggressiveness == Aggressiveness::Careful ? L"Careful" :
					info.HuntAggressiveness == Aggressiveness::Moderate ? L"Moderate" : L"Cursory";
				std::wcout << L"[" << info.HuntName << L": " << aggressiveness << L"] ";
				SetConsoleColor(CLISink::MessageColor::LIGHTGREY);
				std::wcout << L" - " << detections.size() << " detection" << (detections.size() == 1 ? L"" : L"s") << L"!" << std::endl;
				for(auto detection : detections){
					if(detection->Type == DetectionType::File){
						auto lpFileDetection = std::static_pointer_cast<FILE_DETECTION>(detection); 
						std::wcout << L"\tPotentially malicious file detected - " << lpFileDetection->wsFileName << L" (hash is " << lpFileDetection->hash << L")" << std::endl;
					} else if(detection->Type == DetectionType::Process){
						auto lpProcessDetection = std::static_pointer_cast<PROCESS_DETECTION>(detection);
						std::wcout << L"\tPotentially malicious process detected - " << lpProcessDetection->wsImageName << L" (PID is " << lpProcessDetection->PID << L")" << std::endl;
					} else if(detection->Type == DetectionType::Service){
						auto lpServiceDetection = std::static_pointer_cast<SERVICE_DETECTION>(detection);
						std::wcout << L"\tPotentially malicious service detected - " << lpServiceDetection->wsServiceName << L" (PID is " << lpServiceDetection->ServicePID << L")" << std::endl;
					} else if(detection->Type == DetectionType::Registry){
						auto lpRegistryDetection = std::static_pointer_cast<REGISTRY_DETECTION>(detection);
						std::wcout << L"\tPotentially malicious registry key detected - " << lpRegistryDetection->wsRegistryKeyPath << (lpRegistryDetection->wsRegistryKeyValue.length() ? L": " : L"") << lpRegistryDetection->wsRegistryKeyValue << std::endl;
					} else {
						std::wcout << L"\tUnknown detection type!" << std::endl;
					}
				}
				if(message.size() > 0){
					std::cout << "\tAssociated Message: " << message << std::endl;
				}
			} else {
				std::cout << CLISink::MessagePrepends[static_cast<WORD>(level.severity)] << " ";
				SetConsoleColor(CLISink::MessageColor::LIGHTGREY);
				std::cout << message << std::endl;
			}
		}
	}

	bool CLISink::operator==(const LogSink& sink) const {
		return (bool) dynamic_cast<const CLISink*>(&sink);
	}
}