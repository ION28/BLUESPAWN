#include <Windows.h>

#include <iostream>

#include "util/log/ServerSink.h"
#include "common/StringUtils.h"

namespace Log {

	gpb::Aggressiveness ServerSink::HuntAggressivenessToGPB(const Aggressiveness& info) {
		return gpb::Aggressiveness();
	}

	std::vector<gpb::Tactic> ServerSink::HuntTacticsToGPB(DWORD info) {
		return std::vector<gpb::Tactic>();
	}

	std::vector<gpb::Category> ServerSink::HuntCategoriesToGPB(DWORD info) {
		return std::vector<gpb::Category>();
	}

	std::vector<gpb::DataSource> ServerSink::HuntDatasourcesToGPB(DWORD info) {
		return std::vector<gpb::DataSource>();
	}

	gpb::HuntInfo ServerSink::HuntInfoToGPB(const HuntInfo& info) {
		gpb::HuntInfo gpbInfo;

		gpbInfo.set_huntname(WidestringToString(info.HuntName));
		gpbInfo.set_huntaggressiveness(HuntAggressivenessToGPB(info.HuntAggressiveness));

		auto huntTactics = HuntTacticsToGPB(info.HuntTactics);
		for(int i = 0; i < huntTactics.size(); i++)
			gpbInfo.set_hunttactics(i, huntTactics[i]);

		auto huntCategories = HuntCategoriesToGPB(info.HuntCategories);
		for (int i = 0; i < huntCategories.size(); i++)
			gpbInfo.set_huntcategories(i, huntCategories[i]);

		auto huntDatasources = HuntDatasourcesToGPB(info.HuntDatasources);
		for (int i = 0; i < huntDatasources.size(); i++)
			gpbInfo.set_huntdatasources(i, huntDatasources[i]);

		gpbInfo.set_huntstarttime(info.HuntStartTime);
    
		return gpbInfo;
	}

	std::vector<gpb::FileReactionData> ServerSink::GetFileReactions(const std::vector<std::shared_ptr<DETECTION>>& detections) {
		std::vector<gpb::FileReactionData> fileDetections;

		for (auto& detection : detections) {
			// Extract all FILE_DETECTION objects
			if (detection->Type == DetectionType::File) {
				auto fileDetection = std::static_pointer_cast<FILE_DETECTION>(detection);

				gpb::FileReactionData gpbFileDetection;

				fileDetections.emplace_back(gpbFileDetection);
			}
		}

		return fileDetections;
	}

	std::vector<gpb::RegistryReactionData> ServerSink::GetRegistryReactions(const std::vector<std::shared_ptr<DETECTION>>& detections) {
		return std::vector<gpb::RegistryReactionData>();
	}

	std::vector<gpb::ProcessReactionData> ServerSink::GetProcessReactions(const std::vector<std::shared_ptr<DETECTION>>& detections) {
		return std::vector<gpb::ProcessReactionData>();
	}

	std::vector<gpb::ServiceReactionData> ServerSink::GetServiceReactions(const std::vector<std::shared_ptr<DETECTION>>& detections) {
		return std::vector<gpb::ServiceReactionData>();
	}

	void ServerSink::LogMessage(const LogLevel& level, const std::string& message, const std::optional<HuntInfo> info, 
		const std::vector<std::shared_ptr<DETECTION>>& detections){
		if (!level.Enabled())
			return;

		gpb::HuntMessage huntMessage{};
		huntMessage.set_allocated_info(&HuntInfoToGPB(*info));
		huntMessage.set_extramessage(message);
	}

	bool ServerSink::operator==(const LogSink& sink) const {
		return (bool) dynamic_cast<const ServerSink*>(&sink);
	}
}