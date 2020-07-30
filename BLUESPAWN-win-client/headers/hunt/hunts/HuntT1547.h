#pragma once
#include "../Hunt.h"

namespace Hunts {

    /**
	 * HuntT1547 looks for malicious boot or logon autostart execution activity 
     * 
     * T1547.001: examines the registry for run keys and filesystem for startup items
     * T1547.002: examines the registry and filesystem for malicious APs
     * T1547.004: examines the registry for Winlogon helper persistence
     * T1547.005: examines the registry and filesystem for malicious SSPs
     * T1547.010: examines the registry for bad port monitors
	 * 
	 * @scans Cursory checks for bad DLLs configured as port monitors
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
    class HuntT1547 : public Hunt {
        private:
        std::wstring t1547_001 = L"001: Registry Run Keys / Startup Folder";
        std::wstring t1547_002 = L"002: Authentication Package";
        std::wstring t1547_004 = L"004: Winlogon Helper DLL";
        std::wstring t1547_005 = L"005: Security Support Provider";
        std::wstring t1547_010 = L"010: Port Monitors";

        std::vector<std::wstring> RunKeys;

        public:
        HuntT1547();

        virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
        virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
    };
}   // namespace Hunts
