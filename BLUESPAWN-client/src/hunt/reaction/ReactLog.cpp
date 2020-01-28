#include <string>
#include <iostream>

#include "hunt/reaction/Log.h"

#include "util/log/HuntLogMessage.h"

namespace Reactions {
	void LogReaction::LogBeginHunt(const HuntInfo& info){
		_HuntLogMessage = std::optional{ Log::HuntLogMessage{ info, Log::_LogHuntSinks } };
		HuntBegun = true;
	}
	void LogReaction::LogEndHunt(){
		*_HuntLogMessage << Log::endlog;
		_HuntLogMessage = std::nullopt;
		HuntBegun = false;
	}
	void LogReaction::LogFileIdentified(std::shared_ptr<FILE_DETECTION> detection){
		if(HuntBegun){
			_HuntLogMessage->AddDetection(std::static_pointer_cast<DETECTION>(detection));
		} else {
			LOG_ERROR("Potentially malicious file " << detection->wsFileName << " detected outside of a hunt!");
		}
	}
	void LogReaction::LogRegistryKeyIdentified(std::shared_ptr<REGISTRY_DETECTION> detection){
		if(HuntBegun){
			_HuntLogMessage->AddDetection(std::static_pointer_cast<DETECTION>(detection));
		} else {
			LOG_ERROR("Potentially malicious registry key " << detection->wsRegistryKeyPath << (detection->wsRegistryKeyValue.length() ? L": " : L"") << detection->wsRegistryKeyValue << " detected outside of a hunt!");
		}
	}
	void LogReaction::LogProcessIdentified(std::shared_ptr<PROCESS_DETECTION> detection){
		if(HuntBegun){
			_HuntLogMessage->AddDetection(std::static_pointer_cast<DETECTION>(detection));
		} else {
			LOG_ERROR("Potentially malicious process " << detection->wsImageName << " (PID " << detection->PID << ") detected outside of a hunt!");
		}
	}
	void LogReaction::LogServiceIdentified(std::shared_ptr<SERVICE_DETECTION> detection){
		if(HuntBegun){
			_HuntLogMessage->AddDetection(std::static_pointer_cast<DETECTION>(detection));
		} else {
			LOG_ERROR("Potentially malicious service " << detection->wsServiceName << " detected outside of a hunt!");
		}
	}
	void LogReaction::LogEventIdentified(std::shared_ptr<EVENT_DETECTION> detection) {
		if (HuntBegun) {
			_HuntLogMessage->AddDetection(std::static_pointer_cast<DETECTION>(detection));
		}
		else {
			//LOG_ERROR("Potentially malicious service " << detection->wsServiceName << " detected outside of a hunt!");
		}
	}

	LogReaction::LogReaction() : 
		_HuntLogMessage{ std::nullopt }{
		vStartHuntProcs.emplace_back(   std::bind(&LogReaction::LogBeginHunt,             this, std::placeholders::_1));
		vEndHuntProcs.emplace_back(     std::bind(&LogReaction::LogEndHunt,               this                       ));
		vRegistryReactions.emplace_back(std::bind(&LogReaction::LogRegistryKeyIdentified, this, std::placeholders::_1));
		vFileReactions.emplace_back(    std::bind(&LogReaction::LogFileIdentified,        this, std::placeholders::_1));
		vProcessReactions.emplace_back( std::bind(&LogReaction::LogProcessIdentified,     this, std::placeholders::_1));
		vServiceReactions.emplace_back( std::bind(&LogReaction::LogServiceIdentified,     this, std::placeholders::_1));
		vEventReactions.emplace_back(	std::bind(&LogReaction::LogEventIdentified,		  this, std::placeholders::_1));
	}
}