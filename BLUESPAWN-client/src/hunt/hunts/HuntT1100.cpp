#include "hunt/hunts/HuntT1100.h"

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"

namespace Hunts {
	HuntT1100::HuntT1100() : Hunt(L"T1100 - Web Shells") {
		smatch match_index;

		dwSupportedScans = (DWORD) Aggressiveness::Cursory | (DWORD) Aggressiveness::Normal;
		dwCategoriesAffected = (DWORD) Category::Files;
		dwSourcesInvolved = (DWORD) DataSource::FileSystem;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
	}

	void HuntT1100::SetRegexAggressivenessLevel(Aggressiveness aLevel) {
		//PHP regex credit to: https://github.com/emposha/PHP-Shell-Detector
		php_vuln_functions.assign(R"(preg_replace.*\/e|`.*?\$.*?`|\bcreate_function\b|\bpassthru\b|\bshell_exec\b|\bexec\b|\bbase64_decode\b|\bedoced_46esab\b|\beval\b|\bsystem\b|\bproc_open\b|\bpopen\b|\bcurl_exec\b|\bcurl_multi_exec\b|\bparse_ini_file\b|\bshow_source\b)");

		if (aLevel == Aggressiveness::Cursory) {
			asp_indicators.assign(R"(\bcmd.exe\b|\bpowershell.exe\b|\bwscript.shell\b|\bprocessstartinfo\b|createobject\("scripting.filesystemobject"\))");
			jsp_indicators.assign(R"(\bcmd.exe\b|\bpowershell.exe\b)");
		}
		else if (aLevel == Aggressiveness::Normal) {
			asp_indicators.assign(R"(\bcmd.exe\b|\bpowershell.exe\b|\bwscript.shell\b|\bprocessstartinfo\b|\bcreatenowindow\b|\bcmd\b|\beval request\b|\bexecute request\b|\boscriptnet\b|createobject\("scripting.filesystemobject"\))");
			jsp_indicators.assign(R"(\bcmd.exe\b|\bpowershell.exe\b|\bgetruntime\(\)\.exec\b)");
		}
	}

	void HuntT1100::AddDirectoryToSearch(const std::wstring& sFileName){
		web_directories.emplace_back(sFileName);
	}

	void HuntT1100::AddFileExtensionToSearch(const std::wstring& sFileExtension) {
		web_exts.emplace_back(sFileExtension);
	}

	int HuntT1100::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1100 - Web Shells at level Cursory");
		reaction.BeginHunt(GET_INFO());
		SetRegexAggressivenessLevel(Aggressiveness::Cursory);

		int identified = 0;

		for (wstring path : web_directories) {
			FileSystem::Folder* f = new FileSystem::Folder((LPCWSTR)path.c_str());
			FileSystem::FileSearchAttribs attribs;
			attribs.extensions = web_exts;
			std::vector<FileSystem::File*>* files = f->GetFiles(&attribs, -1);
			for (const auto& entry : *files) {
				long offset = 0;
				long targetAmount = 1000000;
				CHAR* read = (CHAR *)calloc(targetAmount + 1, 1);
				DWORD amountRead = 0;
				wstring file_ext = entry->GetFileAttribs().extension;
				do {
					entry->Read(read, offset, targetAmount, amountRead);
					read[amountRead] = '\0';
					string sus_file(read);
					transform(sus_file.begin(), sus_file.end(), sus_file.begin(), ::tolower);
					if (file_ext.compare(L".php") == 0) {
						if (regex_search(sus_file, match_index, php_vuln_functions)) {
							LOG_ERROR("Located likely web shell in file " << entry.path().string() << " in text " << sus_file.substr(match_index.position(), match_index.length()));
						}
					}
					else if (file_ext.substr(0, 4).compare(L".jsp") == 0) {
						if (regex_search(sus_file, match_index, jsp_indicators)) {
							LOG_ERROR("Located likely web shell in file " << entry.path().string() << " in text " << sus_file.substr(match_index.position(), match_index.length()));
						}
					}
					else if (file_ext.substr(0, 3).compare(L".as") == 0) {
						if (regex_search(sus_file, match_index, asp_indicators)) {
							identified++;
							LOG_ERROR("Located likely web shell in file " << entry.path().string() << " in text " << sus_file.substr(match_index.position(), match_index.length()));
						}
					}
					offset += amountRead - 1000;
				} while (targetAmount <= amountRead);
			}
			//Cleanup
			while (!files->empty()) {
				delete files->at(files->size() - 1);
				files->pop_back();
			}
			delete files;
			delete f;
		}
		reaction.EndHunt();
		return identified;
		return 0;
	}

	int HuntT1100::ScanModerate(const Scope& scope, Reaction reaction){
		return 0;
		LOG_INFO("Hunting for T1100 - Web Shells at level Moderate");
		reaction.BeginHunt(GET_INFO());
		SetRegexAggressivenessLevel(Aggressiveness::Moderate);

		int identified = 0;

		for (wstring path : web_directories) {
			FileSystem::Folder* f = new FileSystem::Folder((LPCWSTR)path.c_str());
			FileSystem::FileSearchAttribs attribs;
			attribs.extensions = web_exts;
			std::vector<FileSystem::File*>* files = f->GetFiles(&attribs, -1);
			for (const auto& entry : *files) {
				long offset = 0;
				long targetAmount = 1000000;
				CHAR* read = (CHAR*)calloc(targetAmount + 1, 1);
				DWORD amountRead = 0;
				wstring file_ext = entry->GetFileAttribs().extension;
				do {
					entry->Read(read, offset, targetAmount, amountRead);
					read[amountRead] = '\0';
					string sus_file(read);
					transform(sus_file.begin(), sus_file.end(), sus_file.begin(), ::tolower);

					if (file_ext.compare(L".php") == 0) {
						if (regex_search(sus_file, match_index, php_vuln_functions)) {
							identified++;
							LOG_ERROR("Located likely web shell in file " << entry.path().string() << " in text " << sus_file.substr(match_index.position(), match_index.length()));
						}
					}
					else if (file_ext.substr(0, 4).compare(L".jsp") == 0) {
						if (regex_search(sus_file, match_index, jsp_indicators)) {
							identified++;
							LOG_ERROR("Located likely web shell in file " << entry.path().string() << " in text " << sus_file.substr(match_index.position(), match_index.length()));
						}
					}

					else if (file_ext.substr(0, 3).compare(L".as") == 0) {
						if (regex_search(sus_file, match_index, asp_indicators)) {
							identified++;
							LOG_ERROR("Located likely web shell in file " << entry.path().string() << " in text " << sus_file.substr(match_index.position(), match_index.length()));
						}
					}					offset += amountRead - 1000;
				} while (targetAmount <= amountRead);
			}
			//Cleanup
			while (!files->empty()) {
				delete files->at(files->size() - 1);
				files->pop_back();
			}
			delete files;
			delete f;
		}		

		reaction.EndHunt();
		return identified;
	}
}