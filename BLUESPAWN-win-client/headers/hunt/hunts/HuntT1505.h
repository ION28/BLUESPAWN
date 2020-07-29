#pragma once
#include <regex>
#include <string>
#include <vector>

#include "../Hunt.h"

namespace Hunts {

    /**
	 * HuntT1505 looks for the abuse of legitimate extensible software components
     * T1505.003: examines the locations of web roots, looking for files that are likely to be
	 * webshells.
	 */
    class HuntT1505 : public Hunt {
        private:
        std::wstring t1505_003 = L"003: Web Shell";

        std::vector<std::wstring> web_directories = { L"C:\\inetpub\\wwwroot", L"C:\\xampp\\htdocs" };
        std::vector<std::wstring> web_exts = { L".php",  L".jsp",  L".jspx", L".asp",
                                               L".aspx", L".asmx", L".ashx", L".ascx" };
        std::regex php_vuln_functions{};
        std::regex asp_indicators{};
        std::regex jsp_indicators{};
        std::smatch match_index;

        public:
        HuntT1505();

        virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope);
        virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents();
    };
}   // namespace Hunts
