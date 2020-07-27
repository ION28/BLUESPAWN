#pragma once
#include "../Hunt.h"

namespace Hunts {

	/**
	 * HuntT1031 examines the registry for additions/changes to Services configured
	 * in the registry such as an extra Dll it launches based on a specific value
	 */
	class HuntT1031 : public Hunt {
	public:
		HuntT1031();

		virtual std::vector<std::shared_ptr<Detection>> RunHunt(
			IN CONST Scope& scope
		) override;

		virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
	};
}