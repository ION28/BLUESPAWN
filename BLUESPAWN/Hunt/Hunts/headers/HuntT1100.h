#pragma once
#include "Hunt.h"
#include "Reaction.h"
#include "Log.h"

#include "../../../Logging/headers/Output.h"
#include "../../FileSystem/headers/FileSystem.h"

#include <string>
#include <vector>
#include <regex>

namespace Hunts {

	/**
	 * HuntT1100 scans the locations of web roots, looking for files that are likely to be
	 * webshells.
	 * 
	 * @scans Cursory XXXXXXXXXXXXXXXXXXXXXXXXXX
	 * @scans Moderate XXXXXXXXXXXXXXXXXXXXXXXXXX
	 * @scans Careful XXXXXXXXXXXXXXXXXXXXXXXXXX
	 * @scans Aggressive XXXXXXXXXXXXXXXXXXXXXXXXXX
	 */
	class HuntT1100 : public Hunt {
	private:
		std::vector<std::string> web_directories{ "C:\\inetpub\\wwwroot", "C:\\xampp\\htdocs" };
		std::vector<std::string> web_exts{ ".php", ".jsp", ".jspx", ".asp", ".aspx", ".asmx", ".ashx", ".ascx" };
		regex php_vuln_functions;
		regex asp_indicators;
		regex jsp_indicators;
		smatch match_index;

		void SetRegexAggressivenessLevel(Aggressiveness::Aggressiveness aLevel);

	public:
		HuntT1100(HuntRegister& record);

		void AddDirectoryToSearch(std::string sFileName);
		void AddFileExtensionToSearch(std::string sFileExtension);

		int ScanCursory(Scope& scope, Reaction* reaction = new Reactions::Log());
		int ScanModerate(Scope& scope, Reaction* reaction = new Reactions::Log());
	};
}