#include <Windows.h>

#include <iostream>

#include "util/log/CLISink.h"

namespace Log {

	void CLISink::SetConsoleColor(CLISink::MessageColor color){
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(hConsole, static_cast<WORD>(color));
	}

	CLISink::CLISink() : hMutex{ CreateMutexW(nullptr, false, L"Local\\CLI-Mutex") } {}

	void CLISink::LogMessage(const LogLevel& level, const std::wstring& message){
		auto mutex = AcquireMutex(hMutex);
		if(level.Enabled()){
			SetConsoleColor(CLISink::PrependColors[static_cast<WORD>(level.severity)]);

			if(level.severity == Severity::LogHunt){
				std::wcout << L"[" << info->HuntName << L"] ";
				SetConsoleColor(CLISink::MessageColor::LIGHTGREY);
				std::wcout << L" - " << detections.size() << " detection" << (detections.size() == 1 ? L"" : L"s") << L"!" << std::endl;
				for(auto detection : detections){
					if(detection->Type == DetectionType::File){
						auto lpFileDetection = std::static_pointer_cast<FILE_DETECTION>(detection); 
						std::wcout << L"\tPotentially malicious file detected - " << lpFileDetection->wsFilePath << L" (hash is " << StringToWidestring(lpFileDetection->hash) << L")" << std::endl;
					} else if(detection->Type == DetectionType::Process){
						auto lpProcessDetection = std::static_pointer_cast<PROCESS_DETECTION>(detection);
						std::wcout << L"\tPotentially malicious process detected - " << lpProcessDetection->wsImagePath << L" (PID is " << lpProcessDetection->PID << L")" << std::endl;
					} else if(detection->Type == DetectionType::Service){
						auto lpServiceDetection = std::static_pointer_cast<SERVICE_DETECTION>(detection);
						std::wcout << L"\tPotentially malicious service detected - " << lpServiceDetection->wsServiceName << L" (Path is " << lpServiceDetection->wsServiceExecutablePath << L")" << std::endl;
					} else if(detection->Type == DetectionType::Registry){
						auto lpRegistryDetection = std::static_pointer_cast<REGISTRY_DETECTION>(detection);
						std::wcout << L"\tPotentially malicious registry key detected - " << lpRegistryDetection->value.key.ToString() << L": " << lpRegistryDetection->value.wValueName
							<< L" with data " << lpRegistryDetection->value.ToString() << std::endl;
					} else if (detection->Type == DetectionType::Event) {
						auto lpEvtDet = std::static_pointer_cast<EVENT_DETECTION>(detection);
						std::wcout << L"\tPotentially malicious event detected:" << std::endl;
						std::wcout << "\t\tChannel: " << lpEvtDet->channel << std::endl;
						std::wcout << "\t\tEvent ID: " << lpEvtDet->eventID << std::endl;
						std::wcout << "\t\tEvent Record ID: " << lpEvtDet->eventRecordID << std::endl;
						std::wcout << "\t\tTime Created: " << lpEvtDet->timeCreated << std::endl;
						for (auto iter = lpEvtDet->params.begin(); iter != lpEvtDet->params.end(); ++iter) {
							std::wcout << "\t\t" << iter->first << ": " << iter->second << std::endl;
						}

					} else {
						std::wcout << L"\tUnknown detection type!" << std::endl;
					}
				}
				if(message.size() > 0){
					std::cout << "\tAssociated Message: " << message << std::endl;
				}
			} else {
				std::wcout << CLISink::MessagePrepends[static_cast<WORD>(level.severity)] << " ";
				SetConsoleColor(CLISink::MessageColor::LIGHTGREY);
				std::wcout << message << std::endl;
			}
		}
	}

	bool CLISink::operator==(const LogSink& sink) const {
		return (bool) dynamic_cast<const CLISink*>(&sink);
	}
}