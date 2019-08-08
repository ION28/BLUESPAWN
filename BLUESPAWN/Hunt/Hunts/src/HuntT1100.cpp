#include "hunts/HuntT1100.h"

#include "filesystem/FileSystem.h"
#include "logging/Log.h"

namespace Hunts {
	HuntT1100::HuntT1100(HuntRegister& record) : Hunt(record) {
		smatch match_index;

		dwSupportedScans = Aggressiveness::Cursory | Aggressiveness::Moderate;
		dwStuffAffected = AffectedThing::Files;
		dwSourcesInvolved = DataSource::FileSystem;
		dwTacticsUsed = Tactic::Persistence | Tactic::PrivilegeEscalation;
	}

	void HuntT1100::SetRegexAggressivenessLevel(Aggressiveness::Aggressiveness aLevel) {
		//PHP regex credit to: https://github.com/emposha/PHP-Shell-Detector
		php_vuln_functions.assign(R"(preg_replace.*\/e|`.*?\$.*?`|\bcreate_function\b|\bpassthru\b|\bshell_exec\b|\bexec\b|\bbase64_decode\b|\bedoced_46esab\b|\beval\b|\bsystem\b|\bproc_open\b|\bpopen\b|\bcurl_exec\b|\bcurl_multi_exec\b|\bparse_ini_file\b|\bshow_source\b)");

		if (aLevel == Aggressiveness::Cursory) {
			asp_indicators.assign(R"(\bcmd.exe\b|\bpowershell.exe\b|\bwscript.shell\b|\bprocessstartinfo\b|createobject\("scripting.filesystemobject"\))");
			jsp_indicators.assign(R"(\bcmd.exe\b|\bpowershell.exe\b)");
		}
		else if (aLevel == Aggressiveness::Moderate) {
			asp_indicators.assign(R"(\bcmd.exe\b|\bpowershell.exe\b|\bwscript.shell\b|\bprocessstartinfo\b|\bcreatenowindow\b|\bcmd\b|\beval request\b|\bexecute request\b|\boscriptnet\b|createobject\("scripting.filesystemobject"\))");
			jsp_indicators.assign(R"(\bcmd.exe\b|\bpowershell.exe\b|\bgetruntime\(\)\.exec\b)");
		}
	}

	void HuntT1100::AddDirectoryToSearch(std::string sFileName){
		web_directories.emplace_back(sFileName);
	}

	void HuntT1100::AddFileExtensionToSearch(std::string sFileExtension) {
		web_exts.emplace_back(sFileExtension);
	}

	int HuntT1100::ScanCursory(Scope& scope, Reaction* reaction){
		LOG_INFO("Hunting for T1100 - Web Shells at level Cursory");
		SetRegexAggressivenessLevel(Aggressiveness::Cursory);

		int identified = 0;

		for (string path : web_directories) {
			for (const auto& entry : fs::recursive_directory_iterator(path)) {
				string file_ext = entry.path().extension().string();
				transform(file_ext.begin(), file_ext.end(), file_ext.begin(), ::tolower);
				if (find(web_exts.begin(), web_exts.end(), file_ext) != web_exts.end()) {
					string sus_file = GetFileContents(entry.path().wstring().c_str());
					transform(sus_file.begin(), sus_file.end(), sus_file.begin(), ::tolower);

					if (file_ext.compare(".php") == 0) {
						if (regex_search(sus_file, match_index, php_vuln_functions)) {
							LOG_ERROR("Located likely web shell in file " << entry.path().string() << " in text " << sus_file.substr(match_index.position(), match_index.length()));
						}
					} else if (file_ext.substr(0, 4).compare(".jsp") == 0) {
						if (regex_search(sus_file, match_index, jsp_indicators)) {
							LOG_ERROR("Located likely web shell in file " << entry.path().string() << " in text " << sus_file.substr(match_index.position(), match_index.length()));
						}
					} else if (file_ext.substr(0, 3).compare(".as") == 0) {
						if (regex_search(sus_file, match_index, asp_indicators)) {
							identified++;
							LOG_ERROR("Located likely web shell in file " << entry.path().string() << " in text " << sus_file.substr(match_index.position(), match_index.length()));
						}
					}
				}
			}
		}

		return identified;
	}

	int HuntT1100::ScanModerate(Scope& scope, Reaction* reaction) {
		LOG_INFO("Hunting for T1100 - Web Shells at level Moderate");
		SetRegexAggressivenessLevel(Aggressiveness::Moderate);

		int identified = 0;

		for (string path : web_directories) {
			for (const auto& entry : fs::recursive_directory_iterator(path)) {
				string file_ext = entry.path().extension().string();
				transform(file_ext.begin(), file_ext.end(), file_ext.begin(), ::tolower);
				if (find(web_exts.begin(), web_exts.end(), file_ext) != web_exts.end()) {
					string sus_file = GetFileContents(entry.path().wstring().c_str());
					transform(sus_file.begin(), sus_file.end(), sus_file.begin(), ::tolower);

					if (file_ext.compare(".php") == 0) {
						if (regex_search(sus_file, match_index, php_vuln_functions)) {
							identified++;
							LOG_ERROR("Located likely web shell in file " << entry.path().string() << " in text " << sus_file.substr(match_index.position(), match_index.length()));
						}
					}
					else if (file_ext.substr(0, 4).compare(".jsp") == 0) {
						if (regex_search(sus_file, match_index, jsp_indicators)) {
							identified++;
							LOG_ERROR("Located likely web shell in file " << entry.path().string() << " in text " << sus_file.substr(match_index.position(), match_index.length()));
						}
					}

					else if (file_ext.substr(0, 3).compare(".as") == 0) {
						if (regex_search(sus_file, match_index, asp_indicators)) {
							identified++;
							LOG_ERROR("Located likely web shell in file " << entry.path().string() << " in text " << sus_file.substr(match_index.position(), match_index.length()));
						}
					}
				}
			}
		}		

		return identified;
	}
}