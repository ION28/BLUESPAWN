#include "util/eventlogs/EventLogItem.h"

namespace EventLogs {

	std::wstring EventLogItem::GetProperty(std::wstring prop) {
		std::wstring val;

		auto it = this->props.find(prop);
		if (it != this->props.end())
			val = it->second;

		return val;
	}
	std::unordered_map<std::wstring, std::wstring> EventLogItem::GetProperties() {
		return this->props;
	}
	std::wstring EventLogItem::GetChannel() {
		return this->channel;
	}
	std::wstring EventLogItem::GetTimeCreated() {
		return this->timeCreated;
	}
	std::wstring EventLogItem::GetXML() {
		return this->rawXML;
	}
	unsigned int EventLogItem::GetEventID() {
		return this->eventID;
	}
	unsigned int EventLogItem::GetEventRecordID() {
		return this->eventRecordID;
	}

	void EventLogItem::SetProperty(std::wstring& prop, std::wstring& value) {
		auto it = this->props.find(prop);
		if (it != this->props.end())
			this->props.erase(it);

		this->props.insert(std::make_pair(prop, value));
	}
	void EventLogItem::SetChannel(std::wstring& channel) {
		this->channel = channel;
	}
	void EventLogItem::SetTimeCreated(std::wstring& time) {
		this->timeCreated = time;
	}
	void EventLogItem::SetXML(std::wstring& xml) {
		this->rawXML = xml;
	}
	void EventLogItem::SetEventID(unsigned int id) {
		this->eventID = id;
	}
	void EventLogItem::SetEventRecordID(unsigned int id) {
		this->eventRecordID = id;
	}

}