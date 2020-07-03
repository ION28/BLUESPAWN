#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1036 examines the local file system for executables in user writable
	 * locations in %WINDIR%
	 * 
	 * @scans Cursory checks all such writable folders for executable files
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1036 : public Hunt {
	private:
		std::vector<std::wstring> susExts = { L".bat", L".cmd", L".exe", L".dll", L".js", L".jse",
					L".lnk", L".ps1", L".sct", L".vb", L".vbe", L".vbs", L".vbscript", L".hta" };

		// Credit: https://twitter.com/mattifestation/status/1172520995472756737/photo/1
		std::vector<std::wstring> writableFolders = {
			L"%WINDIR%\\System32\\Microsoft\\crypto\\rsa\\machinekeys",
			L"%WINDIR%\\System32\\tasks_migrated\\microsoft\\windows\\pla\\system",
			L"%WINDIR%\\Syswow64\\tasks\\microsoft\\windows\\pla\\system",
			L"%WINDIR%\\debug\\WIA",
			L"%WINDIR%\\System32\\Tasks",
			L"%WINDIR%\\Syswow64\\Tasks",
			L"%WINDIR%\\Tasks",
			L"%WINDIR%\\Registration\\crmlog",
			L"%WINDIR%\\System32\\com\\dmp",
			L"%WINDIR%\\System32\\fxstmp",
			L"%WINDIR%\\System32\\spool\\drivers\\color",
			L"%WINDIR%\\System32\\spool\\printers",
			L"%WINDIR%\\System32\\spool\\servers",
			L"%WINDIR%\\Syswow64\\com\\dmp",
			L"%WINDIR%\\Syswow64\\fxstmp",
			L"%WINDIR%\\Temp",
			L"%WINDIR%\\tracing"
		};
	public:
		HuntT1036();

		virtual int ScanCursory(const Scope& scope, Reaction reaction) override;
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}