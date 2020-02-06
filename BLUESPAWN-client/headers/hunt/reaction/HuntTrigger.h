#pragma once
#include "Reaction.h"

#include "hunt/Hunt.h"
#include "hunt/HuntRegister.h"

namespace Reactions {

	class HuntTriggerReaction : public Reaction {
	private:
		Hunt* hunt;
		Aggressiveness level;
		const Scope scope;
		Reaction reaction;
		HuntRegister& record;

	public:
		HuntTriggerReaction(HuntRegister& record, Hunt* hunt, const Scope& scope, Aggressiveness level, Reaction& reaction);

		void EventIdentified(std::shared_ptr<EVENT_DETECTION> detection);
	};
}

