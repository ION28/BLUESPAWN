#pragma once
#include "../Hunt.h"

namespace Hunts {

    /**
	 * HuntT1547 looks for malicious boot or logon autostart execution activity 
     * 
     * T1547.001: examines the registry for run keys and filesystem for startup items
     * T1547.002: examines the registry and filesystem for malicious APs
     * T1547.003: examines the registry and filesystem for malicious time providers
     * T1547.004: examines the registry for Winlogon helper persistence
     * T1547.005: examines the registry and filesystem for malicious SSPs
     * T1547.010: examines the registry for bad port monitors
	 * 
	 * @scans Cursory checks for bad DLLs configured as port monitors
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
    class HuntT1547 : public Hunt {

        std::vector<std::wstring> RunKeys;

        public:
        HuntT1547();

        void Subtechnique001(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);
        void Subtechnique002(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);
        void Subtechnique003(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);
        void Subtechnique004(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);
        void Subtechnique005(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);
        void Subtechnique010(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);

        virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
        virtual std::vector<std::pair<std::unique_ptr<Event>, Scope>> GetMonitoringEvents() override;
    };
}   // namespace Hunts
