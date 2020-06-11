#include "util/eventlogs/XpathQuery.h"

namespace EventLogs {

	XpathQuery::XpathQuery(const std::string& path, const ParamList attributes, std::optional<std::string> value) :
		path(path), attributes(attributes), value(value) {
		this->query = generateQuery();
	}

	std::string XpathQuery::ToString() {
		return query;
	}

	bool XpathQuery::SearchesByValue() {
		return value.has_value();
	}

	std::string XpathQuery::generateQuery() {
		// Replace last '/' of the path with '[' unless there are attributes
		// and no value (aka, a query for the existance of an attribute)
		std::string query;

		if (value || attributes.size() == 0) {
			std::size_t found = path.find_last_of("/");
			query = path.substr(0, found) + "[" + path.substr(found + 1);
		}
		else
			query = path;

		if (attributes.size() > 0) {
			query += "[";

			// Add attributes seperated by ' and '
			auto it = attributes.begin();
			query += "@" + it->first + "=" + it->second;
			it++;
			for (; it != attributes.end(); it++)
				query += " and @" + it->first + "=" + it->second;

			query += "]";
		}

		// Add the value if it exists
		if (value)
			query += "=" + value.value();

		// Close the upper path if the last '/' of the path was
		// replaced with '['
		if (value || attributes.size() == 0)
			query += "]";

		return query;
	}

}