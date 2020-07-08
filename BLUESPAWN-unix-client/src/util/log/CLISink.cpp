

#include <iostream>

#include "util/log/CLISink.h"
#include "user/CLI.h"

namespace Log {

	void CLISink::SetConsoleColor(const MessageColor color){
		printf("%s", GetColorStr(color).c_str());
	}

	CLISink::CLISink(){
		pthread_mutex_init(&hMutex, NULL);
	}

	void CLISink::LogMessage(const LogLevel& level, const std::string& message, const std::optional<HuntInfo> info, const std::vector<std::shared_ptr<DETECTION>>& detections){
		auto mutex = AcquireMutex(hMutex);
		if(level.Enabled()){
			SetConsoleColor(CLISink::PrependColors[static_cast<int>(level.severity)]);

			if(level.severity == Severity::LogHunt){
				std::string aggressiveness = info->HuntAggressiveness == Aggressiveness::Intensive ? "Intensive" :
					info->HuntAggressiveness == Aggressiveness::Normal ? "Normal" : "Cursory";
				std::cout << "[" << info->HuntName << ": " << aggressiveness << "] ";
				SetConsoleColor(MessageColor::BOLDWHITE);
				std::cout << " - " << detections.size() << " detection" << (detections.size() == 1 ? "" : "s") << "!" << std::endl;
				for(auto detection : detections){
					if(detection->Type == DetectionType::File){
						auto lpFileDetection = std::static_pointer_cast<FILE_DETECTION>(detection); 
						std::cout << "\tPotentially malicious file detected - " << lpFileDetection->wsFilePath << " (MD5 is " << lpFileDetection->md5 << ")" << std::endl;
					} else if(detection->Type == DetectionType::Process){
						auto lpProcessDetection = std::static_pointer_cast<PROCESS_DETECTION>(detection);
						std::cout << "\tPotentially malicious process detected - " << lpProcessDetection->wsImagePath << " (PID is " << lpProcessDetection->PID << ")" << std::endl;
					} else if(detection->Type == DetectionType::Service){
						auto lpServiceDetection = std::static_pointer_cast<SERVICE_DETECTION>(detection);
						std::cout << "\tPotentially malicious service detected - " << lpServiceDetection->wsServiceName << " (PID is " << lpServiceDetection->ServicePID << ")" << std::endl;
					} else if (detection->Type == DetectionType::Event) {
						auto lpEvtDet = std::static_pointer_cast<EVENT_DETECTION>(detection);
						std::cout << "\tPotentially malicious event detected:" << std::endl;
						std::cout << "\t\tChannel: " << lpEvtDet->channel << std::endl;
						std::cout << "\t\tEvent ID: " << lpEvtDet->eventID << std::endl;
						std::cout << "\t\tEvent Record ID: " << lpEvtDet->eventRecordID << std::endl;
						std::cout << "\t\tTime Created: " << lpEvtDet->timeCreated << std::endl;
						for (auto iter = lpEvtDet->params.begin(); iter != lpEvtDet->params.end(); ++iter) {
							std::cout << "\t\t" << iter->first << ": " << iter->second << std::endl;
						}

					} else {
						std::cout << "\tUnknown detection type!" << std::endl;
					}
				}
				if(message.size() > 0){
					std::cout << "\tAssociated Message: " << message << std::endl;
				}
			} else {
				std::cout << CLISink::MessagePrepends[static_cast<int>(level.severity)] << " ";
				SetConsoleColor(MessageColor::BOLDWHITE);
				std::cout << message << std::endl;
			}

			SetConsoleColor(MessageColor::RESET);
		}
	}

	bool CLISink::operator==(const LogSink& sink) const {
		return (bool) dynamic_cast<const CLISink*>(&sink);
	}
}