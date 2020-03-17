#pragma once
#include "../Hunt.h"

#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1015 looks for Windows Accessibility Features to be messed with in some way
	 * 
	 * @scans Cursory checks for any Debugger keys + binaries are signed
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1015 : public Hunt {
	private:
		std::vector<std::wstring> vAccessibilityBinaries = { L"sethc.exe", L"utilman.exe", L"osk.exe", L"Magnify.exe",
			L"Narrator.exe", L"DisplaySwitch.exe", L"AtBroker.exe" };
		std::wstring wsIFEO = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
		std::wstring wsIFEOWow64 = L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";

		int HuntT1015::EvaluateRegistry(Reaction& reaction);
		int HuntT1015::EvaluateFiles(Reaction& reaction);
	public:
		HuntT1015();

		virtual int ScanCursory(const Scope& scope, Reaction reaction);
		virtual int ScanNormal(const Scope& scope, Reaction reaction);
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}