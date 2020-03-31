#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1060 examines associated Registry Run Keys
	 */
	class HuntT1060 : public Hunt {
	private:
		std::vector<std::wstring> RunKeys;
	public:
		HuntT1060();

		virtual std::vector<std::shared_ptr<DETECTION>> RunHunt(const Scope& scope);
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}