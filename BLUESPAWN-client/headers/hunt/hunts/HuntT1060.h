#pragma once
#include "../Hunt.h"

namespace Hunts {

	/**
	 * HuntT1060 examines associated Registry Run Keys
	 */
	class HuntT1060 : public Hunt {
	private:
		std::vector<std::wstring> RunKeys;

	public:
		HuntT1060();

		virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope);
		virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
	};
}