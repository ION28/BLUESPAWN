#pragma once
#include <string>
#include <unordered_map>

#include "common/wrappers.hpp"

namespace EventLogs {

	/*class EventWrapper : public GenericWrapper<EVT_HANDLE> {
	public:
		EventWrapper(EVT_HANDLE handle) :
			GenericWrapper(handle, std::function<void(EVT_HANDLE)>(EvtClose), INVALID_HANDLE_VALUE){};
	};

	class EventLogItem {
		public:
			std::string GetProperty(std::string prop) const;
			std::unordered_map<std::string, std::string> GetProperties() const;
			std::string GetChannel() const;
			std::string GetTimeCreated() const;
			std::string GetXML() const;
			unsigned int GetEventID() const;
			unsigned int GetEventRecordID() const;

			void SetProperty(std::string& property, std::string& value);
			void SetChannel(std::string& channel);
			void SetTimeCreated(std::string& time);
			void SetXML(std::string& xml);
			void SetEventID(unsigned int id);
			void SetEventRecordID(unsigned int id);

		private:
			unsigned int eventID;
			unsigned int eventRecordID;
			std::string timeCreated;
			std::string channel;
			std::string rawXML;
			std::unordered_map<std::string, std::string> props;
	};
	*/

}