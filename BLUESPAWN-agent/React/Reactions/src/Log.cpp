#include <string>
#include <iostream>

#include "reactions/Log.h"

#include "logging/HuntLogMessage.h"

namespace Reactions {
	void LogReaction::BeginHunt(const HuntInfo& info){
		_HuntLogMessage = { info, Log::_LogHuntSinks };
		HuntBegun = true;
	}
	void LogReaction::EndHunt(){
		_HuntLogMessage << Log::endlog;
		_HuntLogMessage = { HuntInfo{}, std::vector<std::reference_wrapper<Log::LogSink>>{} };
		HuntBegun = false;
	}
	void LogReaction::FileIdentified(FILE_DETECTION* detection){
		if(HuntBegun){
			LOG_HUNT_DETECTION(detection);
		} else {
			LOG_ERROR("Potentially malicious file " << detection->wsFileName << " detected outside of a hunt!");
		}
	}
	void LogReaction::RegistryKeyIdentified(REGISTRY_DETECTION* detection){
		if(HuntBegun){
			LOG_HUNT_DETECTION(detection);
		} else {
			LOG_ERROR("Potentially malicious registry key " << detection->wsRegistryKeyPath << (detection->wsRegistryKeyValue.length() ? L": " : L"") << detection->wsRegistryKeyValue << " detected outside of a hunt!");
		}
	}
	void LogReaction::ProcessIdentified(PROCESS_DETECTION* detection){
		if(HuntBegun){
			LOG_HUNT_DETECTION(detection);
		} else {
			LOG_ERROR("Potentially malicious process " << detection->wsImageName << " (PID " << detection->PID << ") detected outside of a hunt!");
		}
	}
	void LogReaction::ServiceIdentified(SERVICE_DETECTION* detection){
		if(HuntBegun){
			LOG_HUNT_DETECTION(detection);
		} else {
			LOG_ERROR("Potentially malicious service " << detection->wsServiceName << " detected outside of a hunt!");
		}
	}

	LogReaction::LogReaction() : 
		_HuntLogMessage{ HuntInfo{}, std::vector<std::reference_wrapper<Log::LogSink>>{} }{
		vStartHuntProcs.emplace_back(std::bind(&LogReaction::BeginHunt, this, std::placeholders::_1));
		vEndHuntProcs.emplace_back(std::bind(&LogReaction::EndHunt, this));
		vRegistryReactions.emplace_back(std::bind(&LogReaction::RegistryKeyIdentified, this, std::placeholders::_1));
		vFileReactions.emplace_back(std::bind(&LogReaction::FileIdentified, this, std::placeholders::_1));
		vProcessReactions.emplace_back(std::bind(&LogReaction::ProcessIdentified, this, std::placeholders::_1));
		vServiceReactions.emplace_back(std::bind(&LogReaction::ServiceIdentified, this, std::placeholders::_1));
	}
}