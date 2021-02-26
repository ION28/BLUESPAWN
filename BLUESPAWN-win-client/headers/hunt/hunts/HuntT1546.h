#pragma once

#include "../Hunt.h"

namespace Hunts {

    /**
	 * HuntT1546 looks for event triggered persistence attacks. Currently works below:
     * T1546.002: examines the system for malicious screensavers
     * T1546.007: examines the system for malicious Netsh Helper DLLs
     * T1546.008: examines Windows Accessibility Features to see if they have been messed
     * T1546.009: examines the installed AppCertDlls to see if any are malicious
     * t1546.010: examines the installed AppInit_Dlls to see if any are malicious
     * t1546.011: examines the installed shims to see if any are malicious
     * T1546.012: examines IFEOs for debuggers and silent process exit hooks
     * T1546.015: examines CLSID registry values to detect COM hijacking
	 */
    class HuntT1546 : public Hunt {
        std::vector<std::wstring> vAccessibilityBinaries = { L"sethc.exe",   L"utilman.exe",  L"osk.exe",
                                                             L"Magnify.exe", L"Narrator.exe", L"DisplaySwitch.exe",
                                                             L"AtBroker.exe" };

        std::wstring wsIFEO = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";

        public:
        HuntT1546();

        void Subtechnique002(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);
        void Subtechnique007(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);
        void Subtechnique008(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);
        void Subtechnique009(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);
        void Subtechnique010(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);
        void Subtechnique011(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);
        void Subtechnique012(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);
        void Subtechnique015(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);

        virtual std::vector<std::shared_ptr<Detection>> RunHunt(IN CONST Scope& scope) override;
        virtual std::vector<std::pair<std::unique_ptr<Event>, Scope>> GetMonitoringEvents() override;
    };
}   // namespace Hunts
