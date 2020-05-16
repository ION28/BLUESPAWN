#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1031 examines the registry for additions/changes to Services configured
	 * in the registry such as an extra Dll it launches based on a specific value
	 * 
	 * @scans Cursory checks for a ServerLevelPluginDll to be configured on the DNS Service
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1031 : public Hunt {
	private:
		std::vector<std::wstring> vSuspicious = { L"cmd.exe", L"powershell.exe", L"cscript.exe", L"wscript.exe", L"net.exe", L"net1.exe" };
	public:
		HuntT1031();

		virtual int ScanCursory(const Scope& scope, Reaction reaction) override;
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}