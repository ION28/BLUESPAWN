#include "hunt/hunts/HuntT1100.h"

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"
#include "common/StringUtils.h"

namespace Hunts {
	HuntT1100::HuntT1100() : Hunt(L"T1100 - Web Shells") {
		std::smatch match_index;

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

		for (std::wstring path : web_directories) {
			auto f = FileSystem::Folder(path);
			FileSystem::FileSearchAttribs attribs;
			attribs.extensions = web_exts;
			std::vector<FileSystem::File> files = f.GetFiles(attribs, -1);
			for (const auto& entry : files) {
				long offset = 0;
				unsigned long targetAmount = 1000000;
				DWORD amountRead = 0;
				std::wstring file_ext = entry.GetFileAttribs().extension;
				do {
					auto read = entry.Read(targetAmount, offset, &amountRead);
					read.SetByte(amountRead, '\0');
					std::string sus_file = ToLowerCaseA(*read.ReadString());
					if (file_ext.compare(L".php") == 0) {
						if (regex_search(sus_file, match_index, php_vuln_functions)) {
							identified++;
							reaction.FileIdentified(std::make_shared<FILE_DETECTION>(entry.GetFilePath().substr(entry.GetFilePath().find_last_of(L"\\/")), entry.GetFilePath()));
							LOG_ERROR("Located likely web shell in file " << WidestringToString(entry.GetFilePath())<< " in text " << sus_file.substr(match_index.position(), match_index.length()));
						}
					}
					else if (file_ext.substr(0, 4).compare(L".jsp") == 0) {
						if (regex_search(sus_file, match_index, jsp_indicators)) {
							identified++;
							reaction.FileIdentified(std::make_shared<FILE_DETECTION>(entry.GetFilePath().substr(entry.GetFilePath().find_last_of(L"\\/")), entry.GetFilePath()));
							LOG_ERROR("Located likely web shell in file " << WidestringToString(entry.GetFilePath()) << " in text " << sus_file.substr(match_index.position(), match_index.length()));
						}
					}
					else if (file_ext.substr(0, 3).compare(L".as") == 0) {
						if (regex_search(sus_file, match_index, asp_indicators)) {
							identified++;
							reaction.FileIdentified(std::make_shared<FILE_DETECTION>(entry.GetFilePath().substr(entry.GetFilePath().find_last_of(L"\\/")), entry.GetFilePath()));
							LOG_ERROR("Located likely web shell in file " << WidestringToString(entry.GetFilePath()) << " in text " << sus_file.substr(match_index.position(), match_index.length()));
						}
					}
					offset += amountRead - 1000;
				} while (targetAmount <= amountRead);
			}
		}
		reaction.EndHunt();
		return identified;
	}

	int HuntT1100::ScanNormal(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1100 - Web Shells at level Normal");
		reaction.BeginHunt(GET_INFO());
		SetRegexAggressivenessLevel(Aggressiveness::Normal);

		int identified = 0;

		for (std::wstring path : web_directories) {
			FileSystem::Folder f = FileSystem::Folder(path);
			FileSystem::FileSearchAttribs attribs;
			attribs.extensions = web_exts;
			std::vector<FileSystem::File> files = f.GetFiles(attribs, -1);
			for (const auto& entry : files) {
				long offset = 0;
				long targetAmount = 1000000;
				DWORD amountRead = 0;
				auto file_ext = entry.GetFileAttribs().extension;
				do {
					auto read = entry.Read(targetAmount, offset, &amountRead);
					read.SetByte(amountRead, '\0');
					std::string sus_file = ToLowerCaseA(*read.ReadString());
					if (file_ext.compare(L".php") == 0) {
						if (regex_search(sus_file, match_index, php_vuln_functions)) {
							identified++;
							reaction.FileIdentified(std::make_shared<FILE_DETECTION>(entry.GetFilePath().substr(entry.GetFilePath().find_last_of(L"\\/")), entry.GetFilePath()));
							LOG_ERROR("Located likely web shell in file " << WidestringToString(entry.GetFilePath()) << " in text " << sus_file.substr(match_index.position(), match_index.length()));
						}
					}
					else if (file_ext.substr(0, 4).compare(L".jsp") == 0) {
						if (regex_search(sus_file, match_index, jsp_indicators)) {
							identified++;
							reaction.FileIdentified(std::make_shared<FILE_DETECTION>(entry.GetFilePath().substr(entry.GetFilePath().find_last_of(L"\\/")), entry.GetFilePath()));
							LOG_ERROR("Located likely web shell in file " << WidestringToString(entry.GetFilePath()) << " in text " << sus_file.substr(match_index.position(), match_index.length()));
						}
					}

					else if (file_ext.substr(0, 3).compare(L".as") == 0) {
						if (regex_search(sus_file, match_index, asp_indicators)) {
							identified++;
							reaction.FileIdentified(std::make_shared<FILE_DETECTION>(entry.GetFilePath().substr(entry.GetFilePath().find_last_of(L"\\/")), entry.GetFilePath()));
							LOG_ERROR("Located likely web shell in file " << WidestringToString(entry.GetFilePath()) << " in text " << sus_file.substr(match_index.position(), match_index.length()));
						}
					}
					offset += amountRead - 1000;
				} while (targetAmount <= amountRead);
			}
		}		
		reaction.EndHunt();
		return identified;
	}
}
