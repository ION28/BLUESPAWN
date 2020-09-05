#include <string>
#include <iostream>

#include "reaction/RemoveValue.h"
#include "util/configurations/Registry.h"
#include "util/wrappers.hpp"
#include "user/bluespawn.h"
#include "util/log/Log.h"

namespace Reactions{

	void RemoveValueReaction::React(IN Detection& detection){
		auto& data{ std::get<RegistryDetectionData>(detection.data) };
		if(data.value){
			if(Bluespawn::io.GetUserConfirm(L"Registry key `" + data.key.ToString() + L"` contains potentially "
											"malicious value `" + data.value->wValueName + L"` with data `" + 
											data.value->ToString() + L"`. Remove this value?") == 1){
				auto type{ data.key.GetValueType(data.value->wValueName) };
				if(data.key.GetValueType(data.value->wValueName) == data.value->GetType()){
					if(!data.key.RemoveValue(data.value->wValueName)){
						LOG_ERROR("Unable to remove registry value `" << data.value->ToString() << "`: `" <<
								  data.value->wValueName << "` (Error " << GetLastError() << ")");
					} else{
						detection.DetectionStale = true;
					}
				} else{
					if(type == RegistryType::REG_MULTI_SZ_T){
						auto val{ *data.key.GetValue<std::vector<std::wstring>>(data.value->wValueName) };
						for(size_t idx{ 0 }; idx < val.size(); idx++){
							if(val[idx] == std::get<std::wstring>(data.value->data)){
								val.erase(val.begin() + idx);
								idx--;
							}
						}
						if(!data.key.SetValue<std::vector<std::wstring>>(data.value->wValueName, val)){
							LOG_ERROR("Unable to remove registry value `" << data.value->ToString() << "`: `" <<
									  data.value->wValueName << "` (Error " << GetLastError() << ")");
						} else{
							detection.DetectionStale = true;
						}
					} else{
						LOG_ERROR("Unable to remove registry value `" << data.value->ToString() << "` from `" <<
								  data.value->wValueName << "` (Error " << GetLastError() << ")");
					}
				}
			}
		}
	}

	bool RemoveValueReaction::Applies(IN CONST Detection& detection){
		return !detection.DetectionStale && detection.type == DetectionType::RegistryDetection;
	}
}
