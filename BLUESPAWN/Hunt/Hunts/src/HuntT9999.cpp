#include "hunts/HuntT9999.h"
#include "logging/Log.h"

namespace Hunts {
	HuntT9999::HuntT9999(HuntRegister& record) : Hunt(record) {
		dwSupportedScans = Aggressiveness::Cursory;
		dwStuffAffected = AffectedThing::Files;
		dwSourcesInvolved = DataSource::FileSystem;
		dwTacticsUsed = Tactic::Persistence;
	}

	void HuntT9999::AddFileToSearch(std::string sFileName){
		vFileNames.emplace_back(sFileName);
	}

	int HuntT9999::ScanCursory(Scope& scope, Reaction* reaction){
		LOG_INFO("Hunting for T9999 - Example Hunt at level Cursory");

		int identified = 0;

		for(std::string sFileName : vFileNames){
			if(!scope.FileIsInScope(sFileName.c_str())){
				continue;
			}

			DWORD dwFileAttributes = GetFileAttributesA(sFileName.c_str());

			if(dwFileAttributes != 0xFFFFFFFF){
				if(reaction->SupportsReactions(Reactions::IdentifyFile)){
					WIN32_FIND_DATAA data{};
					reaction->FileIdentified(CreateFileA(sFileName.c_str(), SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
				}
				 
				identified++;
			}
		}

		return identified;
	}
}