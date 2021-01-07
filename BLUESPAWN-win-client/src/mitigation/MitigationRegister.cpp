#include "mitigation/MitigationRegister.h"
#include "util/log/Log.h"
#include "util/StringUtils.h"
#include "nlohmann/json.hpp"
#include "user/bluespawn.h"
#include "user/CLI.h"
#include "../resources/resource.h"

using json = nlohmann::json;

MitigationsConfiguration::MitigationsConfiguration(EnforcementLevel level){
	for(auto& mitigation : Bluespawn::mitigationRecord.registeredMitigations){
		configurations.emplace(&mitigation, MitigationConfiguration{ level });
	}
}

MitigationRegister::MitigationRegister(){
	auto hRsrcInfo = FindResourceW(nullptr, MAKEINTRESOURCE(DefaultMitigations), L"textfile");
	if(!hRsrcInfo){
		LOG_ERROR("Unable to load default mitigations");
		throw std::exception("Unable to load default mitigations");
	}

	auto hRsrc = LoadResource(nullptr, hRsrcInfo);
	if(!hRsrc){
		Bluespawn::io.AlertUser(L"Unable to load default mitigations!", -1, ImportanceLevel::HIGH);
		LOG_ERROR("Unable to load default mitigations");
		throw std::exception("Unable to load default mitigations");
	}

	ParseMitigationsJSON(AllocationWrapper{ LockResource(hRsrc), SizeofResource(nullptr, hRsrcInfo) });
}

std::map<Mitigation*, MitigationReport>
MitigationRegister::EnforceMitigations(const MitigationsConfiguration& config) const{
	std::map<Mitigation*, MitigationReport> results;
	for(auto& mitigation : config.configurations){
		results.emplace(mitigation.first, mitigation.first->EnforceMitigation(mitigation.second));
	}
	return results;
}

std::map<Mitigation*, MitigationReport>
MitigationRegister::AuditMitigations(const MitigationsConfiguration& config) const{
	std::map<Mitigation*, MitigationReport> results;
	for(auto& mitigation : config.configurations){
		results.emplace(mitigation.first, mitigation.first->AuditMitigation(mitigation.second));
	}
	return results;
}

bool MitigationRegister::ParseMitigationsJSON(const std::wstring& filepath){
	return ParseMitigationsJSON(FileSystem::File(filepath).Read());
}

bool MitigationRegister::ParseMitigationsJSON(const AllocationWrapper& contents){
	if(contents.GetSize()){
		try{
			auto data{ 
				json::parse(nlohmann::detail::input_adapter(contents.GetAsPointer<char>(), contents.GetSize())) };
			if(data.find("mitigations") == data.end()){
				throw std::exception("unable to find mitigations");
			}
			auto mitigations{ data["mitigations"] };
			for(auto& mitigation : mitigations){
				registeredMitigations.push_back(Mitigation(mitigation));
			}
			return true;
		} catch(std::exception& e){
			Bluespawn::io.AlertUser(L"Unable to parse JSON for mitigations! Ensure there are no errors in your "
									"configuration file. Error: " + StringToWidestring(e.what()), -1, 
									ImportanceLevel::HIGH);
			LOG_ERROR("Unable to parse mitigations");
		}
	}
	return false;
}