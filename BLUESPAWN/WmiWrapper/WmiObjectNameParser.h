#pragma once
#ifndef WMI_OBJECT_NAME_PARSER_H
#define WMI_OBJECT_NAME_PARSER_H

#include "stdafx.h"
#include <string>

/** Used to extract the namespace and classtype from a relative path to a WMI class
    Accepts format relatve_namespace/classType, exe CIMV2/Win32_Process
    Paths can use any mix of / or \\
*/
class WmiObjectNameParser {

	public:
		static std::string getNamespace(const std::string& wmiObjectName);
		static std::string getClassType(const std::string& wmiObjectName);

	private:
		static std::string replaceAll(std::string str, const std::string& from, const std::string& to);

};

#endif
