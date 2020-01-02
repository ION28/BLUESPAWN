#pragma once
#include "../Hunt.h"
#include "util/reaction/Reaction.h"
#include "util/reaction/Log.h"

#include <string>
#include <vector>
#include <regex>

namespace Hunts {

	/**
	 * HuntT1100 scans the locations of web roots, looking for files that are likely to be
	 * webshells.
	 * 
	 * @scans Cursory Checks for obvious bad functions that indicate a webshell
	 * @scans Moderate Adds more suspicious indicators in the regex to look for
	 * @scans Careful Scan not supported.
	 * @scans Aggressive Scan not supported.
	 */
	class HuntT1100 : public Hunt {
	private:
		std::vector<std::string> web_directories = { "C:\\inetpub\\wwwroot", "C:\\xampp\\htdocs" };
		std::vector<std::string> web_exts = { ".php", ".jsp", ".jspx", ".asp", ".aspx", ".asmx", ".ashx", ".ascx" };
		std::regex php_vuln_functions{};
		std::regex asp_indicators{};
		std::regex jsp_indicators{};
		std::smatch match_index{};

		void SetRegexAggressivenessLevel(Aggressiveness aLevel);

	public:
		HuntT1100(HuntRegister& record);

		void AddDirectoryToSearch(const std::string& sFileName);
		void AddFileExtensionToSearch(const std::string& sFileExtension);

		virtual int ScanCursory(const Scope& scope, Reaction reaction = Reactions::LogReaction());
		virtual int ScanModerate(const Scope& scope, Reaction reaction = Reactions::LogReaction());
	};
}