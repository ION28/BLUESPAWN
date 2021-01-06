#include "mitigation/MitigationRegister.h"
#include "util/log/Log.h"
#include "util/StringUtils.h"
#include "nlohmann/json.hpp"
#include "user/bluespawn.h"

using json = nlohmann::json;

MitigationRegister::MitigationRegister(const IOBase& io) : io(io) {}

bool MitigationRegister::ParseMitigationsJSON(const std::wstring& filepath){
	return ParseMitigationsJSON(FileSystem::File(filepath).Read());
}

bool MitigationRegister::ParseMitigationsJSON(const AllocationWrapper& contents){
	if(contents.GetSize()){
		try{
			auto data{ json::parse(contents.GetAsPointer<char>()) };
			if(data.find("mitigations") == data.end()){
				throw std::exception("unable to find mitigations");
			}
			auto mitigations{ data["mitigations"] };
			for(auto& mitigation : mitigations){
				registeredMitigations.push_back(Mitigation(mitigation));
			}
		} catch(std::exception& e){
			Bluespawn::io.AlertUser(L"Unable to parse JSON for mitigations! Ensure there are no errors in your "
									"configuration file. Error: " + StringToWidestring(e.what()), -1, 
									ImportanceLevel::HIGH);
			return false;
		}
	}
}