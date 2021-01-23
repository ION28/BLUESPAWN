#include "mitigation/policy/EventLogPolicy.h"
#include "util/StringUtils.h"
#include "util/eventlogs/EventLogs.h"

EventLogPolicy::EventLogPolicy(json policy) : MitigationPolicy(policy){
	assert(policy.find("channels") != policy.end());

	for(auto& channel : policy["channels"]){
		channelNames.emplace(StringToWidestring(channel.get<std::string>()));
	}
}

bool EventLogPolicy::Enforce(){
	if(IsEnforced()){
		if(!MatchesSystem()){
			bool enforced = false;
			for(auto& channel : channelNames){
				if(!EventLogs::IsChannelOpen(channel)){
					enforced = enforced && EventLogs::OpenChannel(channel);
				}
			}
			return enforced;
		} else{
			return true;
		}
	} else return MatchesSystem();
}

bool EventLogPolicy::MatchesSystem() const{
	for(auto& channel : channelNames){
		if(!EventLogs::IsChannelOpen(channel)){
			return false;
		}
	}
	return true;
}