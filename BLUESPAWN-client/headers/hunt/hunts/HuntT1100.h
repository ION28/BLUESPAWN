#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

#include <string>
#include <vector>
#include <regex>

namespace Hunts {

	/**
	 * HuntT1100 scans the locations of web roots, looking for files that are likely to be
	 * webshells.
	 */
	class HuntT1100 : public Hunt {
	private:
		std::vector<std::wstring> web_directories = { L"C:\\inetpub\\wwwroot", L"C:\\xampp\\htdocs" };
		std::vector<std::wstring> web_exts = { L".php", L".jsp", L".jspx", L".asp", L".aspx", L".asmx", L".ashx", L".ascx" };
		std::regex php_vuln_functions{};
		std::regex asp_indicators{};
		std::regex jsp_indicators{};
		std::smatch match_index{};

	public:
		HuntT1100();

		void AddDirectoryToSearch(const std::wstring& sFileName);
		void AddFileExtensionToSearch(const std::wstring& sFileExtension);

		virtual std::vector<std::reference_wrapper<Detection>> RunHunt(const Scope& scope);
	};
}