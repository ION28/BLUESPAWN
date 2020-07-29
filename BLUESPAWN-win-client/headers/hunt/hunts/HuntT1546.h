#pragma once

#include "../Hunt.h"

namespace Hunts {

    /**
	 * HuntT1546 looks for event triggered persistence attacks. Currently works below:
     * T1547.007: examines the system for malicious Netsh Helper DLLs
     * T1546.008: examines Windows Accessibility Features to see if they have been messed
     * T1546.009: examines the installed AppCertDlls to see if any are malicious
     * t1546.010: examines the installed AppInit_Dlls to see if any are malicious
     * t1546.011: examines the installed shims to see if any are malicious
     * T1546.012: examines IFEOs for debuggers and silent process exit hooks
     * T1546.015: examines CLSID registry values to detect COM hijacking
	 */
    class HuntT1546 : public Hunt {
        private:
        std::wstring t1546_007 = L"007: Netsh Helper DLL";
        std::wstring t1546_008 = L"008: Accessibility Features";
        std::wstring t1546_009 = L"009: AppCert DLLs";
        std::wstring t1546_010 = L"010: AppInit DLLs";
        std::wstring t1546_011 = L"011: Application Shimming";
        std::wstring t1546_012 = L"012: Image File Execution Options Injection";
        std::wstring t1546_015 = L"015: Component Object Model Hijacking";

        std::vector<std::wstring> vAccessibilityBinaries = { L"sethc.exe",   L"utilman.exe",  L"osk.exe",
                                                             L"Magnify.exe", L"Narrator.exe", L"DisplaySwitch.exe",
                                                             L"AtBroker.exe" };

        std::wstring wsIFEO = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";

        public:
        HuntT1546();

        virtual std::vector<std::shared_ptr<Detection>> RunHunt(IN CONST Scope& scope) override;
        virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
    };
}   // namespace Hunts
