#include "hunts/HuntT1060.h"
#include "hunts/RegistryHunt.hpp"

#include "logging/Log.h"
#include "configuration/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1060::HuntT1060(HuntRegister& record) : Hunt(record) {
		dwSupportedScans = Aggressiveness::Cursory;
		dwStuffAffected = AffectedThing::Configurations;
		dwSourcesInvolved = DataSource::Registry;
		dwTacticsUsed = Tactic::Persistence;
	}

	int HuntT1060::ScanCursory(Scope& scope, Reaction* reaction){
		LOG_INFO("Hunting for T1060 - Registry Run Keys / Startup Folder at level Cursory");

		int identified = 0;
		
		identified += CheckForValues({ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run" }, reaction);
		identified += CheckForValues({ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run" }, reaction);
		identified += CheckForValues({ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" }, reaction);
		identified += CheckForValues({ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" }, reaction);
		identified += CheckForValues({ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" }, reaction);
		identified += CheckForValues({ HKEY_CURRENT_USER, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" }, reaction);
		identified += CheckForValues({ HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" }, reaction);
		identified += CheckForValues({ HKEY_CURRENT_USER, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce" }, reaction);
		identified += CheckForValues({ HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce" }, reaction);
		identified += CheckForValues({ HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" }, reaction);
		identified += CheckForValues({ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" }, reaction);
		identified += CheckForValues({ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" }, reaction);

		identified += CheckForSubkeys({ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run" }, reaction);
		identified += CheckForSubkeys({ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run" }, reaction);
		identified += CheckForSubkeys({ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" }, reaction);
		identified += CheckForSubkeys({ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" }, reaction);
		identified += CheckForSubkeys({ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" }, reaction);
		identified += CheckForSubkeys({ HKEY_CURRENT_USER, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" }, reaction);
		identified += CheckForSubkeys({ HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" }, reaction);
		identified += CheckForSubkeys({ HKEY_CURRENT_USER, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce" }, reaction);
		identified += CheckForSubkeys({ HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce" }, reaction);
		identified += CheckForSubkeys({ HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" }, reaction);
		identified += CheckForSubkeys({ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" }, reaction);
		identified += CheckForSubkeys({ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" }, reaction);

		identified += CheckKey({ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", L"Startup" }, 
			                   L"%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", reaction);
		identified += CheckKey({ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", L"Common Startup"}, 
			                   L"%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", reaction);
		identified += CheckKey({ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", L"Common Startup" }, 
			                   L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", reaction);

		return identified;
	}

}