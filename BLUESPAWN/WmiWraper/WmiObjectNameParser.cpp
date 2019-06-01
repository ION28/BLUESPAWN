#include "stdafx.h"
#include "WmiObjectNameParser.h"

std::string WmiObjectNameParser::getNamespace(const std::string  &wmiObjectName) {
	std::string parsedObjectName = replaceAll(wmiObjectName, "\\", "/");

	int pos = parsedObjectName.find_last_of("/");
	if (pos == std::string::npos)
		return "";

	return parsedObjectName.substr(0, pos);
}

std::string WmiObjectNameParser::getClassType(const std::string &wmiObjectName) {
	std::string parsedObjectName = replaceAll(wmiObjectName, "\\", "/");

	int pos = parsedObjectName.find_last_of("/") + 1;
	if (pos == std::string::npos)
		return parsedObjectName;

	return parsedObjectName.substr(pos);
}

std::string WmiObjectNameParser::replaceAll(std::string str, const std::string & from, const std::string & to) {
	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length();
	}
	return str;
}