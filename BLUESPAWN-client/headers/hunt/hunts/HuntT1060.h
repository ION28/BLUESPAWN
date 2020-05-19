#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1060 examines associated Registry Run Keys
	 * 
	 * @scans Cursory checks the values of the associated Registry Run Keys
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1060 : public Hunt {
	private:
		std::vector<std::wstring> RunKeys;
		int EvaluateFile(const std::wstring& wLaunchString, Reaction& reaction);

	public:
		HuntT1060();

		virtual int ScanCursory(const Scope& scope, Reaction reaction);
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}