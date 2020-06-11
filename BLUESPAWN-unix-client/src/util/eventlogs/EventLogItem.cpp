#include "util/eventlogs/EventLogItem.h"

namespace EventLogs {

	/*std::string EventLogItem::GetProperty(std::string prop) const {
		std::string val;

		auto it = this->props.find(prop);
		if (it != this->props.end())
			val = it->second;

		return val;
	}
	std::unordered_map<std::string, std::string> EventLogItem::GetProperties() const {
		return this->props;
	}
	std::string EventLogItem::GetChannel() const {
		return this->channel;
	}
	std::string EventLogItem::GetTimeCreated() const {
		return this->timeCreated;
	}
	std::string EventLogItem::GetXML() const {
		return this->rawXML;
	}
	unsigned int EventLogItem::GetEventID() const {
		return this->eventID;
	}
	unsigned int EventLogItem::GetEventRecordID() const {
		return this->eventRecordID;
	}

	void EventLogItem::SetProperty(std::string& prop, std::string& value) {
		auto it = this->props.find(prop);
		if (it != this->props.end())
			this->props.erase(it);

		this->props.insert(std::make_pair(prop, value));
	}
	void EventLogItem::SetChannel(std::string& channel) {
		this->channel = channel;
	}
	void EventLogItem::SetTimeCreated(std::string& time) {
		this->timeCreated = time;
	}
	void EventLogItem::SetXML(std::string& xml) {
		this->rawXML = xml;
	}
	void EventLogItem::SetEventID(unsigned int id) {
		this->eventID = id;
	}
	void EventLogItem::SetEventRecordID(unsigned int id) {
		this->eventRecordID = id;
	}*/

}