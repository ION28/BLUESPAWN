#pragma once

#include <string>
#include <vector>
#include <optional>

namespace EventLogs {

	// Duplicate typedef as in EventLogs.h because including EventLogs.h breaks everything
	typedef std::vector<std::pair<std::wstring, std::wstring>> ParamList;

	class XpathQuery {
		public:
			XpathQuery(const std::wstring& path, const ParamList attributes, std::optional<std::wstring> value = std::optional<std::wstring>());
			std::wstring ToString();
			bool SearchesByValue();
		private:
			std::wstring generateQuery();
			std::wstring query;
			std::wstring path;
			const ParamList attributes;
			std::optional<std::wstring> value;
	};

}