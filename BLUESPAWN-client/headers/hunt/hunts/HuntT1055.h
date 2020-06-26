#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"
#include "common/DynamicLinker.h"

namespace Hunts {

	/**
	 * HuntT1055 examines all processes for shellcode injections, injected PE images,
	 * function hooks, and doppelganging. This individual hunt will eventually be broken
	 * into separate hunts
	 */
	class HuntT1055 : public Hunt {

	public:
		HuntT1055();

		virtual std::vector<std::reference_wrapper<Detection>> RunHunt(const Scope& scope) override;
	};
}
