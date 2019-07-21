#include "Hunts.h"

void GoHuntingATTACK() {
	PrintInfoHeader("Hunting for MITRE ATT&CK techniques on the system");
	cout << endl;

	HuntT1004WinlogonHelperDll();
	HuntT1037LogonScripts();
	HuntT1060RegistryRunKeysStartUpFolder();
<<<<<<< HEAD
=======
	HuntT1100WebShell();
>>>>>>> parent of e2aa140... clear out master branch for major restructure
	HuntT1101SecuritySupportProvider();
	HuntT1103AppInitDlls();
	HuntT1131AuthenticationPackage();
	HuntT1138ApplicationShimming();
	HuntT1182AppCertDlls();

	PrintSectionDivider();
}

void GoHuntingWeakSecuritySettings() {
	PrintInfoHeader("Hunting for weak security settings on the system");
	cout << endl;

	HuntWSSRegistryKeys();

	PrintSectionDivider();
}

void HuntWSSRegistryKeys() {
	PrintInfoHeader("Hunting for weak security settings in the Registry");

	const int num_of_keys_to_inspect = 2;
	key keys[num_of_keys_to_inspect] = {
		{HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", L"UserAuthentication", s2ws("1"), REG_DWORD},
		{HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RunAsPPL", s2ws("1"), REG_DWORD},
	};

	ExamineRegistryKeySet(keys, num_of_keys_to_inspect);

	cout << endl;
}

void HuntT1004WinlogonHelperDll() {
	PrintInfoHeader("Hunting for T1004 - Winlogon Helper DLL");

	const int num_of_keys_to_inspect = 7;
	key keys[num_of_keys_to_inspect] = {
		{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", s2ws("explorer.exe"), REG_SZ},
		{HKEY_LOCAL_MACHINE,L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", s2ws("explorer.exe"), REG_SZ},
		{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", s2ws(""), REG_SZ},

		{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit", s2ws("C:\\Windows\\system32\\userinit.exe,"), REG_SZ},
		{HKEY_LOCAL_MACHINE,L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit", s2ws(""), REG_SZ},
		{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit", s2ws(""), REG_SZ},

		{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", L"*", s2ws("*"), REG_SZ},
	};

	ExamineRegistryKeySet(keys, num_of_keys_to_inspect);

	cout << endl;
}

void HuntT1037LogonScripts() {
	PrintInfoHeader("Hunting for T1037 - Logon Scripts");

	const int num_of_keys_to_inspect = 1;
	key keys[num_of_keys_to_inspect] = {
		{HKEY_CURRENT_USER,L"Environment",L"UserInitMprLogonScript", s2ws(""), REG_SZ},
	};

	ExamineRegistryKeySet(keys, num_of_keys_to_inspect);

	cout << endl;
}

void HuntT1060RegistryRunKeysStartUpFolder() {
	PrintInfoHeader("Hunting for T1060 - Registry Run Keys / Startup Folder");

	const int num_of_keys_to_inspect = 15;
	key keys[num_of_keys_to_inspect] = {
		{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"*", s2ws("*"), REG_SZ},
		{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"*", s2ws("*"), REG_SZ},
		{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"*", s2ws("*"), REG_SZ},
		{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"*", s2ws("*"), REG_SZ},
		{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", L"*", s2ws("*"), REG_SZ},
		{HKEY_CURRENT_USER,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", L"*", s2ws("*"), REG_SZ},
		{HKEY_LOCAL_MACHINE,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", L"*", s2ws("*"), REG_SZ},
		{HKEY_CURRENT_USER,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"*", s2ws("*"), REG_SZ},
		{HKEY_LOCAL_MACHINE,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"*", s2ws("*"), REG_SZ},
		{HKEY_LOCAL_MACHINE,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", L"*", s2ws("*"), REG_SZ},
		{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", L"*", s2ws("*"), REG_SZ},
		{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", L"*", s2ws("*"), REG_SZ},
		{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", L"Startup", s2ws("%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"), REG_SZ},
		{HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", L"Common Startup", s2ws("%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"), REG_SZ},
		{HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", L"Common Startup", s2ws("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"), REG_SZ},
	};

	ExamineRegistryKeySet(keys, num_of_keys_to_inspect);

	cout << endl;
}

<<<<<<< HEAD
=======
void HuntT1100WebShell() {
	PrintInfoHeader("Hunting for T1100 - Web Shells");

	vector<string> web_directories{ "C:\\inetpub\\wwwroot", "C:\\xampp\\htdocs" };
	vector<string> web_exts{ ".php", ".jsp", ".jspx", ".asp", ".aspx", ".asmx", ".ashx", ".ascx" };
	//PHP regex credit to: https://github.com/emposha/PHP-Shell-Detector
	regex php_vuln_functions(R"(preg_replace.*\/e|`.*?\$.*?`|\bcreate_function\b|\bpassthru\b|\bshell_exec\b|\bexec\b|\bbase64_decode\b|\bedoced_46esab\b|\beval\b|\bsystem\b|\bproc_open\b|\bpopen\b|\bcurl_exec\b|\bcurl_multi_exec\b|\bparse_ini_file\b|\bshow_source\b)");
	regex asp_indicators(R"(\bcmd.exe\b|\bpowershell.exe\b|\bwscript.shell\b|\bprocessstartinfo\b|\bcreatenowindow\b|\bcmd\b|\beval request\b|\bexecute request\b|\boscriptnet\b|createobject\("scripting.filesystemobject"\))");
	regex jsp_indicators(R"(\bcmd.exe\b|\bpowershell.exe\b|\bgetruntime\(\)\.exec\b)");
	smatch match_index;

	for (string path : web_directories) {
		bool found_bad = false;
		for (const auto& entry : fs::recursive_directory_iterator(path)) {
			string file_ext = entry.path().extension().string();
			transform(file_ext.begin(), file_ext.end(), file_ext.begin(), ::tolower);
			if (find(web_exts.begin(), web_exts.end(), file_ext) != web_exts.end()) {
				string sus_file = GetFileContents(entry.path().wstring().c_str());
				transform(sus_file.begin(), sus_file.end(), sus_file.begin(), ::tolower);
				
				if (file_ext.compare(".php") == 0) {
					if (regex_search(sus_file, match_index, php_vuln_functions)) {
						PrintBadStatus("Located likely web shell: " + entry.path().string());
						PrintInfoStatus("Detected on:");
						cout << sus_file.substr(match_index.position() - 50, 50);
						SetConsoleColor("yellow");
						cout << sus_file.substr(match_index.position(), match_index.length());
						SetConsoleColor("white");
						cout << sus_file.substr(match_index.position() + match_index.length(), 50 ) << endl;
						found_bad = true;
					}
				}
				else if (file_ext.substr(0, 4).compare(".jsp") == 0) {
					if (regex_search(sus_file, match_index, jsp_indicators)) {
						PrintBadStatus("Located likely web shell: " + entry.path().string());
						PrintInfoStatus("Detected on:");
						cout << sus_file.substr(match_index.position() - 50, 50);
						SetConsoleColor("yellow");
						cout << sus_file.substr(match_index.position(), match_index.length());
						SetConsoleColor("white");
						cout << sus_file.substr(match_index.position() + match_index.length(), 50) << endl;
						found_bad = true;
					}
				}
				
				else if (file_ext.substr(0, 3).compare(".as") == 0) {
					if (regex_search(sus_file, match_index, asp_indicators)) {
						PrintBadStatus("Located likely web shell: " + entry.path().string());
						PrintInfoStatus("Detected on:");
						cout << sus_file.substr(match_index.position() - 50, 50);
						SetConsoleColor("yellow");
						cout << sus_file.substr(match_index.position(), match_index.length());
						SetConsoleColor("white");
						cout << sus_file.substr(match_index.position() + match_index.length(), 50) << endl;
						found_bad = true;
					}
				}
			}
		}
		if (!found_bad) {
			PrintGoodStatus("No web shells detected in " + path);
		}
	}

	cout << endl;
}

>>>>>>> parent of e2aa140... clear out master branch for major restructure
void HuntT1101SecuritySupportProvider() {
	PrintInfoHeader("Hunting for T1101 - Security Support Provider");

	key keys[2] = {
		{HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Security Packages", s2ws("*"), REG_MULTI_SZ},
		{HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig", L"Security Packages", s2ws("*"), REG_MULTI_SZ},
	};

	vector<wstring> okSecPackages = { L"\"\"", L"wsauth", L"kerberos", L"msv1_0", L"schannel", L"wdigest", L"tspkg", L"pku2u" };

	for (int i = 0; i < 2; i++) {
		HKEY hKey;
		LONG lRes = RegOpenKeyEx(keys[i].hive, keys[i].path, 0, KEY_READ, &hKey);
		bool bExistsAndSuccess(lRes == ERROR_SUCCESS);

		if (bExistsAndSuccess) {
			wstring key_name = keys[i].key;
			wstring result;
			vector<wstring> target;
			GetRegistryKey(hKey, keys[i].type, result, key_name, target);
			RegCloseKey(hKey);

			bool foundBad = false;
			for (auto& val : target) {
				if (find(okSecPackages.begin(), okSecPackages.end(), val) == okSecPackages.end()) {
					PrintBadStatus("Key is non-default: " + hive2s(keys[i].hive) + (string)"\\" + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
					PrintInfoStatus("Found potentially bad package: " + ws2s(val));
					foundBad = true;
				}
			}
			if (!foundBad) {
				PrintGoodStatus("Key is okay: " + hive2s(keys[i].hive) + (string)"\\" + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
			}
		}
		else {
			PrintGoodStatus("Key is okay: " + hive2s(keys[i].hive) + (string)"\\" + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
		}
	}

	cout << endl;
}

void HuntT1103AppInitDlls() {
	PrintInfoHeader("Hunting for T1103 - AppInit DLLs");

	const int num_of_keys_to_inspect = 4;
	key keys[num_of_keys_to_inspect] = {
		{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", s2ws(""), REG_SZ},
		{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"LoadAppInit_DLLs", s2ws("0"), REG_DWORD},
		{HKEY_LOCAL_MACHINE,L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", s2ws(""), REG_SZ},
		{HKEY_LOCAL_MACHINE,L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"LoadAppInit_DLLs", s2ws("0"), REG_DWORD},
	};

	ExamineRegistryKeySet(keys, num_of_keys_to_inspect);

	cout << endl;
}

void HuntT1131AuthenticationPackage() {
	PrintInfoHeader("Hunting for T1131 - Authentication Package");

	key keys[2] = {
		{HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Authentication Packages", s2ws("*"), REG_MULTI_SZ},
		{HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Notification Packages", s2ws("*"), REG_MULTI_SZ},
	};

	vector<wstring> okAuthPackages = { L"msv1_0", L"SshdPinAuthLsa" };
	vector<wstring> okNotifPackages = { L"scecli" };

	for (int i = 0; i < 2; i++) {
		HKEY hKey;
		LONG lRes = RegOpenKeyEx(keys[i].hive, keys[i].path, 0, KEY_READ, &hKey);
		bool bExistsAndSuccess(lRes == ERROR_SUCCESS);

		if (bExistsAndSuccess) {
			wstring key_name = keys[i].key;
			wstring result;
			vector<wstring> target;
			GetRegistryKey(hKey, keys[i].type, result, key_name, target);
			RegCloseKey(hKey);

			bool foundBad = false;
			for (auto& val : target) {
				if (i == 0) {
					if (find(okAuthPackages.begin(), okAuthPackages.end(), val) == okAuthPackages.end()) {
						PrintBadStatus("Key is non-default: " + hive2s(keys[i].hive) + (string)"\\" + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
						PrintInfoStatus("Found potentially bad package: " + ws2s(val));
						foundBad = true;
					}
				}
				else if (i == 1) {
					if (find(okNotifPackages.begin(), okNotifPackages.end(), val) == okNotifPackages.end()) {
						PrintBadStatus("Key is non-default: " + hive2s(keys[i].hive) + (string)"\\" + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
						PrintInfoStatus("Found potentially bad package: " + ws2s(val));
						foundBad = true;
					}
				}
			}
			if (!foundBad) {
				PrintGoodStatus("Key is okay: " + hive2s(keys[i].hive) + (string)"\\" + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
			}
		}
		else {
			PrintGoodStatus("Key is okay: " + hive2s(keys[i].hive) + (string)"\\" + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
		}
	}

	cout << endl;
}

void HuntT1138ApplicationShimming() {
	PrintInfoHeader("Hunting for T1138 - Application Shimming");

	const int num_of_keys_to_inspect = 2;
	key keys[num_of_keys_to_inspect] = {
		{HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags", L"InstalledSDB", s2ws(""), REG_SZ},
		{HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags", L"Custom", s2ws(""), REG_SZ },
	};

	ExamineRegistryKeySet(keys, num_of_keys_to_inspect);

	cout << endl;
}

void HuntT1182AppCertDlls() {
	PrintInfoHeader("Hunting for T1182 - AppCert DLLs");

	//https://b3n7s.github.io/2018/10/27/AppCert-Dlls.html

	const int num_of_keys_to_inspect = 1;
	key keys[num_of_keys_to_inspect] = {
		{HKEY_LOCAL_MACHINE,L"System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls", L"*", s2ws("*"), REG_SZ},
	};

	ExamineRegistryKeySet(keys, num_of_keys_to_inspect);

	cout << endl;
}