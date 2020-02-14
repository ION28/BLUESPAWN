#pragma once

#include "util/eventlogs/XpathQuery.h"

namespace EventLogs {

	XpathQuery::XpathQuery(const std::wstring& path, const ParamList attributes, std::optional<std::wstring> value) :
		path(path), attributes(attributes), value(value) {
		this->query = generateQuery();
	}

	std::wstring XpathQuery::ToString() {
		return query;
	}

	bool XpathQuery::SearchesByValue() {
		return value.has_value();
	}

	std::wstring XpathQuery::generateQuery() {
		// Replace last '/' of the path with '[' unless there are attributes
		// and no value (aka, a query for the existance of an attribute)
		std::wstring query;

		if (value || attributes.size() == 0) {
			std::size_t found = path.find_last_of(L"/");
			query = path.substr(0, found) + L"[" + path.substr(found + 1);
		}
		else
			query = path;

		if (attributes.size() > 0) {
			query += L"[";

			// Add attributes seperated by ' and '
			auto it = attributes.begin();
			query += L"@" + it->first + L"=" + it->second;
			it++;
			for (; it != attributes.end(); it++)
				query += L" and @" + it->first + L"=" + it->second;

			query += L"]";
		}

		// Add the value if it exists
		if (value)
			query += L"=" + value.value();

		// Close the upper path if the last '/' of the path was
		// replaced with '['
		if (value || attributes.size() == 0)
			query += L"]";

		return query;
	}

}