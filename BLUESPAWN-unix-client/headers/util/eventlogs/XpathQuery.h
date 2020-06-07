#pragma once

#include <string>
#include <vector>
#include <optional>

namespace EventLogs {

	// Duplicate typedef as in EventLogs.h because including EventLogs.h breaks everything
	typedef std::vector<std::pair<std::string, std::string>> ParamList;

	class XpathQuery {
		public:
			XpathQuery(const std::string& path, const ParamList attributes, std::optional<std::string> value = std::optional<std::string>());
			std::string ToString();
			bool SearchesByValue();
		private:
			std::string generateQuery();
			std::string query;
			std::string path;
			const ParamList attributes;
			std::optional<std::string> value;
	};

}