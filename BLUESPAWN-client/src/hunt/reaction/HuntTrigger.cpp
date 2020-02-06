#include "hunt/reaction/HuntTrigger.h"
#include "util/log/huntlogmessage.h"

namespace Reactions {
	HuntTriggerReaction::HuntTriggerReaction(HuntRegister& record, Hunt* hunt, const Scope& scope, Aggressiveness level, Reaction& reaction) :
		record(record), hunt(hunt), level(level), scope(scope), reaction(reaction) {}

	void HuntTriggerReaction::EventIdentified(std::shared_ptr<EVENT_DETECTION> detection) {
		LOG_INFO("Event found through monitoring.");

		record.RunHunt(*hunt, scope, level, reaction);
	}
}