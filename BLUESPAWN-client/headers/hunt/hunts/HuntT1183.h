#pragma once
#include "../Hunt.h"

namespace Hunts {

	/**
	 * HuntT1183 examines the Image File Execution Options for debuggers and silent
	 * process exit hooks
	 */
	class HuntT1183 : public Hunt {
	public:
		HuntT1183();

		virtual std::vector<std::reference_wrapper<Detection>> RunHunt(
			IN CONST Scope& scope
		) override;

		virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
	};
}