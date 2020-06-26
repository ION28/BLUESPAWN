#pragma once
#include "../Hunt.h"

#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"

namespace Hunts {

	/**
	 * HuntT1037 examines the registry and filesystem for logon scripts
	 */
	class HuntT1037 : public Hunt {
	public:
		HuntT1037();

		virtual std::vector<std::reference_wrapper<Detection>> RunHunt(const Scope& scope) override;
		virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
	};
}