#pragma once
#include <string>
#include <unordered_map>

namespace EventLogs {

	class EventLogItem {
		public:
			std::wstring GetProperty(std::wstring prop);
			std::unordered_map<std::wstring, std::wstring> GetProperties();
			std::wstring GetChannel();
			std::wstring GetTimeCreated();
			std::wstring GetXML();
			unsigned int GetEventID();
			unsigned int GetEventRecordID();

			void SetProperty(std::wstring& property, std::wstring& value);
			void SetChannel(std::wstring& channel);
			void SetTimeCreated(std::wstring& time);
			void SetXML(std::wstring& xml);
			void SetEventID(unsigned int id);
			void SetEventRecordID(unsigned int id);

		private:
			unsigned int eventID;
			unsigned int eventRecordID;
			std::wstring timeCreated;
			std::wstring channel;
			std::wstring rawXML;
			std::unordered_map<std::wstring, std::wstring> props;
	};

}