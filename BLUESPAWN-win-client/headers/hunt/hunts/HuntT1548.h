#pragma once

#include "../Hunt.h"

namespace Hunts {

	class HuntT1548 : public Hunt
	{
	public:
		HuntT1548();

		void Subtechnique002(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);

		virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
		virtual std::vector<std::pair<std::unique_ptr<Event>, Scope>> GetMonitoringEvents() override;
	};
}	// namespace Hunts