#pragma once
#include "../Hunt.h"

namespace Hunts {

	/**
	 * HuntT1004 examines Winlogon related registry keys that can be used for
	 * persistence.
	 */
	class HuntT1004 : public Hunt {
	public:
		HuntT1004();

		virtual std::vector<std::shared_ptr<Detection>> RunHunt(
			IN CONST Scope& scope
		) override;

		virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
	};
}